/*
 * Copyright (C) 2004-2026 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// A "nick taker" for networks without NickServ (IRCnet style), implemented
// as a global module.
//
// The admin registers nicknames for a network (Add/Del/List/On/Off sent to
// *keepnick). For every enabled network the module opens a synthetic IRC
// connection ("clone"): a plain TCP/TLS socket with a minimal IRC session
// (PASS/NICK/USER, answers PING), completely independent of any ZNC user.
// When a candidate nick is free, the clone registers with it and just sits
// there. On 433 the clone tries the next candidate on its next attempt
// (numeric suffixes with `Rotation on`).
//
// Handoff: when the real user is online and wants a nick that a clone holds,
// the clone changes its own nick to a temporary one. A nick freed by a NICK
// change can be taken immediately, while a QUIT would trigger IRCnet's nick
// delay. The user then takes the nick (automatically on connect, via their
// own /nick, or after the 433 our release allowed); if they don't manage
// within HANDOFF_TIMEOUT seconds, the clone takes the nick back. After a
// successful handoff the clone disconnects; if the user loses the nick
// later, a new clone is spawned automatically.
//
// Anti-flood: an attempt is started at most every Interval seconds (default
// 30, clamped to 30..3600), repeated failures back off exponentially (capped
// at one hour) and replies that indicate we are not welcome (465, K-line
// ERROR) back off much harder.
//
// On Linux the clone sockets get IP_FREEBIND/IPV6_FREEBIND before they are
// bound to the network's vhost, so the source address may be an unassigned
// address (e.g. from a routed /48). Nothing else in ZNC is affected. Disable
// with `FreeBind off`.
//
// See docs/keepnick.md for details.

#include <znc/Debug.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/Message.h>
#include <znc/Modules.h>
#include <znc/Server.h>
#include <znc/Socket.h>
#include <znc/User.h>
#include <znc/znc.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <map>
#include <utility>
#include <vector>

#include "keepnick_utils.h"

#ifdef __linux__
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif
#define KEEPNICK_HAVE_FREEBIND 1
#endif

// At most this many clone connections and pending DNS lookups in total.
static const unsigned int MAX_CLONES = 32;
// Seconds the clone waits for the user to take the nick before taking it
// back.
static const unsigned int HANDOFF_TIMEOUT = 60;

class CKeepNickMod;

class CKeepNickMod : public CModule {
  public:
    // Events the clone socket reports to the module.
    enum class ECloneEvent {
        Up,           // registered, holding the target nick
        Rejected,     // 432/433/436 during registration
        NickBusy,     // 433/436 on a NICK change after registration
        NickChanged,  // our own NICK change was echoed by the server
        NickLenKnown  // learned NICKLEN from 005
    };

    MODCONSTRUCTOR(CKeepNickMod) {
        AddHelpCommand();
        AddCommand("Add", t_d("<nick> [nick ...]"),
                   t_d("Hold the given nick(s) on this network"),
                   [this](const CString& sLine) { CmdAdd(sLine); });
        AddCommand("Del", t_d("<nick> [nick ...]"),
                   t_d("Stop holding the given nick(s)"),
                   [this](const CString& sLine) { CmdDel(sLine); });
        AddCommand("List", t_d(""),
                   t_d("Show the networks this module holds nicks for"),
                   [this](const CString& sLine) { CmdList(sLine); });
        AddCommand("On", t_d(""), t_d("Enable keepnick on this network"),
                   [this](const CString& sLine) { CmdOnOff(sLine, true); });
        AddCommand("Off", t_d(""), t_d("Disable keepnick on this network"),
                   [this](const CString& sLine) { CmdOnOff(sLine, false); });
        AddCommand("Take", t_d(""),
                   t_d("Give the held nick to this network right now"),
                   [this](const CString& sLine) { CmdTake(sLine); });
        AddCommand("Interval", t_d("[seconds]"),
                   t_d("Show or set the minimum time between attempts"),
                   [this](const CString& sLine) { CmdInterval(sLine); });
        AddCommand("Rotation", t_d("[on|off]"),
                   t_d("Try nick1, nick2... before moving to the next nick"),
                   [this](const CString& sLine) { CmdRotation(sLine); });
        AddCommand("FreeBind", t_d("[on|off]"),
                   t_d("Bind clones to unassigned vhost addresses (Linux "
                       "IP_FREEBIND)"),
                   [this](const CString& sLine) { CmdFreeBind(sLine); });
    }
    ~CKeepNickMod() override {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override;
    void OnModCommand(const CString& sLine) override;
    void OnIRCConnected() override;
    void OnNickMessage(CNickMessage& Message,
                       const std::vector<CChan*>& vChans) override;
    EModRet OnNumericMessage(CNumericMessage& Message) override;
    EModRet OnDeleteUser(CUser& User) override;
    EModRet OnDeleteNetwork(CIRCNetwork& Network) override;

    // ---- called from the clone socket and the DNS job ----

    void OnCloneEvent(ECloneEvent e, class CKeepNickSock* pSock);
    void OnCloneLost(class CKeepNickSock* pSock, bool bKLine);
#ifdef HAVE_PTHREAD
    void OnDNSDone(class CKeepNickDNSJob* pJob);
#endif

    // Runs every 5 seconds from CKeepNickTimer.
    void Tick();

  private:
    struct SPending {
        CString sServerName;
        unsigned short uPort = 6667;
        bool bSSL = false;
        CString sPass;
        CString sNick;
    };

    struct STarget {
        bool bEnabled = true;
        std::vector<CString> vsNicks;
        CKeepNickSock* pClone = nullptr;
        unsigned int uNickLen = 0;    // learned from 005, 0 = unknown
        unsigned int uFailLevel = 0;  // consecutive failures (backoff)
        unsigned int uCursor = 0;     // candidate counter for NextCandidate
        time_t tNextAttempt = 0;
        time_t tHandoffDeadline = 0;  // 0 = no handoff in progress
    };

    // ---- helpers ----

    static CString KeyOf(CIRCNetwork* pNetwork) {
        return KeepNickUtils::NetKey(pNetwork->GetUser()->GetUserName(),
                                     pNetwork->GetName());
    }
    static CString PendingKey(const CString& sKey) { return sKey + "::hold"; }
    CIRCNetwork* FindNet(const CString& sKey) const;
    STarget& NetState(const CString& sKey, CIRCNetwork* pNetwork);
    unsigned int Interval() const { return m_uInterval; }
    unsigned int NickLenOf(const STarget& t, CIRCNetwork* pNetwork) const;
    void Log(CIRCNetwork* pNetwork, const CString& sMsg);
    void SendTakeToUser(CIRCNetwork* pNetwork, const CString& sNick);
    static bool UserOwnsNick(CIRCNetwork* pNetwork,
                             const std::vector<CString>& vsNicks);
    unsigned int CountClones() const;

    // ---- per-network state ----

    void LoadNets();
    void LoadNet(const CString& sKey, CIRCNetwork* pNetwork);
    void SaveNet(const CString& sKey, const STarget& t);
    void ForgetNet(const CString& sKey);
    void ForgetPending(const CString& sKey);
    void TickNet(STarget& t, CIRCNetwork* pNetwork, const CString& sKey);
    void StartClone(STarget& t, CIRCNetwork* pNetwork, const CString& sKey);
    void DropClone(STarget* t);
    void AttemptFailed(STarget& t, CIRCNetwork* pNetwork, bool bKLine,
                       const CString& sWhy);
    void BeginHandoff(STarget& t, CIRCNetwork* pNetwork);
    void HandoffSuccess(STarget& t, CIRCNetwork* pNetwork);

    // ---- commands ----

    CIRCNetwork* NeedNetwork();
    void CmdAdd(const CString& sLine);
    void CmdDel(const CString& sLine);
    void CmdList(const CString& sLine);
    void CmdOnOff(const CString& sLine, bool bOn);
    void CmdTake(const CString& sLine);
    void CmdInterval(const CString& sLine);
    void CmdRotation(const CString& sLine);
    void CmdFreeBind(const CString& sLine);

    // ---- state ----

    std::map<CString, STarget> m_msNets;      // "<user>/<net>" -> state
    std::map<CString, SPending> m_msPending;  // "<user>/<net>::hold" -> args
    unsigned int m_uInterval = 30;
    bool m_bRotation = false;
    bool m_bFreeBind = true;

    friend class CKeepNickSock;
    friend class CKeepNickTimer;
#ifdef HAVE_PTHREAD
    friend class CKeepNickDNSJob;
#endif
};

// The clone connection. The socket is created and connected manually (so
// that IP_FREEBIND can be applied before bind()) and then handed to the
// socket manager via ConnectFD() with the connection state CST_CONNECTWAIT.
// The manager then drives the normal connection life cycle: it reports
// Connected() once the TCP handshake is done and, for SSL sockets, moves the
// socket to CST_CONNECTSSL and runs the TLS handshake, ending in
// SSLHandShakeFinished().
class CKeepNickSock : public CSocket {
  public:
    enum class EState { Registering, Holding, Released };

    CKeepNickSock(CKeepNickMod* pOwner, const CString& sKey,
                  const CString& sNick, const CString& sServer,
                  unsigned short uPort, bool bSSL, const CString& sPass)
        : CSocket(pOwner, "", 0, 300),
          m_pOwner(pOwner),
          m_sKey(sKey),
          m_sTargetNick(sNick),
          m_sServer(sServer),
          m_sPass(sPass),
          m_uPort(uPort),
          m_bSSL(bSSL) {
        SetTimeout(300);
    }
    ~CKeepNickSock() override {}

    // Getters
    const CString& GetKey() const { return m_sKey; }
    const CString& GetNick() const { return m_sNick; }
    const CString& GetTargetNick() const { return m_sTargetNick; }
    const CString& GetServerName() const { return m_sServer; }
    unsigned short GetPort() const { return m_uPort; }
    bool IsTLS() const { return m_bSSL; }
    EState GetState() const { return m_eState; }
    unsigned int GetNickLen() const { return m_uNickLen; }
    // !Getters

    // After Detach() the socket no longer talks to the module; it is either
    // being deleted by the manager or has been forgotten by the module.
    void Detach() { m_pOwner = nullptr; }
    bool IsDetached() const { return m_pOwner == nullptr; }

    void SetTargetIP(const CString& sIP) { m_sTargetIP = sIP; }
    void SetBindIP(const CString& sIP) { m_sBindIP = sIP; }

    CString SockName() const { return "KN:" + m_sKey + "::" + m_sTargetNick; }

    // Creates the socket, applies IP_FREEBIND, binds to the vhost and starts
    // the (non-blocking) TCP connect. The caller adds the socket to the
    // manager afterwards.
    bool Dial(bool bFreeBind);

    // Hand the target nick over to the user: change to a temporary nick.
    void BeginHandoff(const CString& sTempNick) {
        PutIRCLine("NICK " + sTempNick);
    }
    // Take the target nick back.
    void Retake() { PutIRCLine("NICK " + m_sTargetNick); }

    void PutIRCLine(const CString& sLine) { Write(sLine + "\r\n"); }

  private:
    void SendLogin();
    void NotifyOwner(CKeepNickMod::ECloneEvent e);
    void Lost(bool bKLine);

    void Connected() override;
#ifdef HAVE_LIBSSL
    void SSLHandShakeFinished() override;
#endif
    void ReadLine(const CS_STRING& sLine) override;
    void Disconnected() override;
    void ConnectionRefused() override;
    void Timeout() override;
    void SockError(int iErrno, const CString& sDescription) override;

    CKeepNickMod* m_pOwner;
    const CString m_sKey;
    const CString m_sTargetNick;
    const CString m_sServer;
    const CString m_sPass;
    const unsigned short m_uPort;
    const bool m_bSSL;
    CString m_sTargetIP;
    CString m_sBindIP;
    CString m_sNick;
    EState m_eState = EState::Registering;
    unsigned int m_uNickLen = 0;
};

class CKeepNickTimer : public CTimer {
  public:
    CKeepNickTimer(CKeepNickMod* pModule)
        : CTimer(pModule, 5, 0, "KeepNickTick",
                 "Drives the keepnick state machine") {}
    ~CKeepNickTimer() override {}

  protected:
    void RunJob() override;
};

#ifdef HAVE_PTHREAD
// Resolves the IRC server (and the vhost to bind to) on a worker thread and
// hands the numeric addresses back to the main thread, which dials.
class CKeepNickDNSJob : public CModuleJob {
  public:
    CKeepNickDNSJob(CKeepNickMod* pModule, const CString& sKey,
                    const CString& sPendingKey, const CString& sServer,
                    const CString& sBindHost)
        : CModuleJob(pModule, "KeepNickDNS", "Resolving a keepnick endpoint"),
          m_sKey(sKey),
          m_sPendingKey(sPendingKey),
          m_sServer(sServer),
          m_sBindHost(sBindHost) {}
    ~CKeepNickDNSJob() override {
        if (m_pRes) freeaddrinfo(m_pRes);
        if (m_pBindRes) freeaddrinfo(m_pBindRes);
    }

    void runThread() override;
    void runMain() override;

    // Getters
    const CString& GetKey() const { return m_sKey; }
    const CString& GetPendingKey() const { return m_sPendingKey; }
    const CString& GetTargetIP() const { return m_sTargetIP; }
    const CString& GetBindIP() const { return m_sBindIP; }
    bool IsOk() const { return m_bOk; }
    // !Getters

  private:
    static addrinfo* Resolve(const CString& sHost);
    static addrinfo* FindFamily(addrinfo* pRes, int iFamily);
    static CString ToNumeric(const addrinfo* pAI);

    const CString m_sKey;
    const CString m_sPendingKey;
    const CString m_sServer;
    const CString m_sBindHost;
    CString m_sTargetIP;
    CString m_sBindIP;
    addrinfo* m_pRes = nullptr;
    addrinfo* m_pBindRes = nullptr;
    bool m_bOk = false;
};
#endif

// ------------------------- clone socket -------------------------

bool CKeepNickSock::Dial(bool bFreeBind) {
    sockaddr_storage ssTarget;
    socklen_t iTargetLen = 0;
    memset(&ssTarget, 0, sizeof(ssTarget));
    auto pIn6 = (sockaddr_in6*)&ssTarget;
    auto pIn = (sockaddr_in*)&ssTarget;
    if (inet_pton(AF_INET6, m_sTargetIP.c_str(), &pIn6->sin6_addr) == 1) {
        ssTarget.ss_family = AF_INET6;
        pIn6->sin6_port = htons(m_uPort);
        iTargetLen = sizeof(sockaddr_in6);
    } else if (inet_pton(AF_INET, m_sTargetIP.c_str(), &pIn->sin_addr) == 1) {
        ssTarget.ss_family = AF_INET;
        pIn->sin_port = htons(m_uPort);
        iTargetLen = sizeof(sockaddr_in);
    } else {
        return false;
    }

#ifdef HAVE_LIBSSL
    SetSSL(m_bSSL);
#else
    (void)m_bSSL;
#endif
    // Server name for SNI and certificate verification (the target address
    // is a literal IP, so this must be set explicitly).
    SetHostToVerifySSL(m_sServer);

    int fd = socket(ssTarget.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return false;

    bool bBind = !m_sBindIP.empty();
#ifdef KEEPNICK_HAVE_FREEBIND
    if (bBind && bFreeBind) {
        // The vhost address may be unassigned on this host (e.g. a routed
        // /48), so allow binding to it anyway. Without this sockopt the
        // bind() below fails with EADDRNOTAVAIL.
        int on = 1;
        if (ssTarget.ss_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &on, sizeof(on));
        } else {
            setsockopt(fd, SOL_IP, IP_FREEBIND, &on, sizeof(on));
        }
        // Best effort: if the sockopt is unsupported, bind() below fails.
    }
#else
    (void)bFreeBind;
#endif

    if (bBind) {
        sockaddr_storage ssBind;
        socklen_t iBindLen = 0;
        memset(&ssBind, 0, sizeof(ssBind));
        bool bOK = false;
        if (ssTarget.ss_family == AF_INET6) {
            auto pBind6 = (sockaddr_in6*)&ssBind;
            if (inet_pton(AF_INET6, m_sBindIP.c_str(), &pBind6->sin6_addr) ==
                1) {
                ssBind.ss_family = AF_INET6;
                iBindLen = sizeof(sockaddr_in6);
                bOK = true;
            }
        } else {
            auto pBind4 = (sockaddr_in*)&ssBind;
            if (inet_pton(AF_INET, m_sBindIP.c_str(), &pBind4->sin_addr) ==
                1) {
                ssBind.ss_family = AF_INET;
                iBindLen = sizeof(sockaddr_in);
                bOK = true;
            }
        }
        if (!bOK || bind(fd, (const sockaddr*)&ssBind, iBindLen) != 0) {
            close(fd);
            return false;
        }
    }

    int iFlags = fcntl(fd, F_GETFL, 0);
    if (iFlags != -1) iFlags = fcntl(fd, F_SETFL, iFlags | O_NONBLOCK);
    if (iFlags == -1) {
        close(fd);
        return false;
    }
    if (connect(fd, (const sockaddr*)&ssTarget, iTargetLen) != 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return false;
    }

    if (!ConnectFD(fd, fd, SockName(), false, Csock::OUTBOUND)) {
        close(fd);
        return false;
    }
    // The TCP handshake is still in progress; the socket manager finishes it
    // and reports Connected() (or an error) as usual.
    SetConState(Csock::CST_CONNECTWAIT);
    return true;
}

void CKeepNickSock::SendLogin() {
    if (!m_sPass.empty()) PutIRCLine("PASS " + m_sPass);
    PutIRCLine("NICK " + m_sNick);
    PutIRCLine("USER keepnick 0 * :ZNC keepnick");
}

void CKeepNickSock::Connected() {
    CSocket::Connected();
    if (GetSSL()) return;  // the login is sent once TLS is up
    SendLogin();
}

#ifdef HAVE_LIBSSL
void CKeepNickSock::SSLHandShakeFinished() {
    // Verifies the peer certificate against the server name and closes the
    // socket on error.
    CZNCSock::SSLHandShakeFinished();
    if (!IsClosed()) SendLogin();
}
#endif

void CKeepNickSock::ReadLine(const CS_STRING& sRawLine) {
    CString sLine(sRawLine);
    sLine.Trim();
    if (sLine.empty()) return;
    CMessage Msg(sLine);
    const CString& sCmd = Msg.GetCommand();

    if (sCmd.Equals("PING")) {
        PutIRCLine("PONG :" + Msg.GetParam(0));
        return;
    }
    if (sCmd.Equals("ERROR")) {
        CString sText = Msg.GetParamsColon(0).AsLower();
        Lost(sText.Contains("banned") || sText.Contains("k-lined") ||
             sText.Contains("g-lined"));
        Close();
        return;
    }
    if (sCmd.Equals("NICK")) {
        // A NICK message about ourselves: the echo of our own handoff
        // changes drives the state machine.
        if (Msg.GetNick().GetNick().Equals(m_sNick)) {
            // For a NICK line the new nick is the first parameter.
            m_sNick = Msg.GetParam(0);
            m_eState = m_sNick.Equals(m_sTargetNick) ? EState::Holding
                                                     : EState::Released;
            NotifyOwner(CKeepNickMod::ECloneEvent::NickChanged);
        }
        return;
    }

    // Non-numeric commands were handled above; what is left is either a
    // numeric or something we ignore. For a numeric the command is its code.
    const unsigned int uCode = sCmd.ToUInt();
    if (uCode == 0) return;

    switch (uCode) {
        case 1:  // RPL_WELCOME, param 0 is the nick as the server sees it
            m_sNick = Msg.GetParam(0);
            m_eState = EState::Holding;
            NotifyOwner(CKeepNickMod::ECloneEvent::Up);
            break;
        case 5:  // RPL_ISUPPORT, look for NICKLEN=<n>
            for (const CString& s : Msg.GetParamsSplit(1)) {
                if (s.Token(0).Equals("NICKLEN")) {
                    unsigned int uLen = s.Token(1, false, "=").ToUInt();
                    if (uLen > 0) {
                        m_uNickLen = uLen;
                        NotifyOwner(CKeepNickMod::ECloneEvent::NickLenKnown);
                    }
                }
            }
            break;
        case 432:  // ERR_ERRONEUSNICKNAME
        case 433:  // ERR_NICKNAMEINUSE
        case 436:  // ERR_NICKCOLLISION
            if (m_eState == EState::Registering) {
                NotifyOwner(CKeepNickMod::ECloneEvent::Rejected);
            } else {
                NotifyOwner(CKeepNickMod::ECloneEvent::NickBusy);
            }
            break;
        case 465:  // ERR_YOUREBANNEDCREEP
            Lost(true);
            Close();
            break;
        default:
            break;
    }
}

void CKeepNickSock::Disconnected() {
    CSocket::Disconnected();
    Lost(false);
}

void CKeepNickSock::ConnectionRefused() {
    CSocket::ConnectionRefused();
    Lost(false);
}

void CKeepNickSock::Timeout() {
    CSocket::Timeout();
    Lost(false);
}

void CKeepNickSock::SockError(int iErrno, const CString& sDescription) {
    CSocket::SockError(iErrno, sDescription);
    Lost(false);
}

void CKeepNickSock::NotifyOwner(CKeepNickMod::ECloneEvent e) {
    if (m_pOwner) m_pOwner->OnCloneEvent(e, this);
}

void CKeepNickSock::Lost(bool bKLine) {
    if (m_pOwner) m_pOwner->OnCloneLost(this, bKLine);
}

// ------------------------- timer and DNS job -------------------------

void CKeepNickTimer::RunJob() { static_cast<CKeepNickMod*>(m_pModule)->Tick(); }

#ifdef HAVE_PTHREAD
addrinfo* CKeepNickDNSJob::Resolve(const CString& sHost) {
    if (sHost.empty()) return nullptr;
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif
    addrinfo* pRes = nullptr;
    if (getaddrinfo(sHost.c_str(), nullptr, &hints, &pRes) != 0) return nullptr;
    return pRes;
}

addrinfo* CKeepNickDNSJob::FindFamily(addrinfo* pRes, int iFamily) {
    for (addrinfo* p = pRes; p; p = p->ai_next) {
        if (p->ai_family == iFamily && p->ai_socktype == SOCK_STREAM) return p;
    }
    return nullptr;
}

CString CKeepNickDNSJob::ToNumeric(const addrinfo* pAI) {
    if (!pAI) return "";
    char buf[INET6_ADDRSTRLEN];
    if (pAI->ai_family == AF_INET6) {
        inet_ntop(AF_INET6, &((const sockaddr_in6*)pAI->ai_addr)->sin6_addr,
                  buf, sizeof(buf));
    } else if (pAI->ai_family == AF_INET) {
        inet_ntop(AF_INET, &((const sockaddr_in*)pAI->ai_addr)->sin_addr, buf,
                  sizeof(buf));
    } else {
        return "";
    }
    return CString(buf);
}

void CKeepNickDNSJob::runThread() {
    if (wasCancelled()) return;
    m_pRes = Resolve(m_sServer);
    if (!m_pRes) return;
    if (!m_sBindHost.empty()) {
        m_pBindRes = Resolve(m_sBindHost);
        if (!m_pBindRes) return;
        // The bind and destination address families must match; prefer the
        // vhost's IPv6 address if it has one.
        addrinfo* pBind = FindFamily(m_pBindRes, AF_INET6);
        if (!pBind) pBind = FindFamily(m_pBindRes, AF_INET);
        if (!pBind) return;
        addrinfo* pTarget = FindFamily(m_pRes, pBind->ai_family);
        if (!pTarget) return;
        m_sBindIP = ToNumeric(pBind);
        m_sTargetIP = ToNumeric(pTarget);
    } else {
        addrinfo* pTarget = FindFamily(m_pRes, AF_INET6);
        if (!pTarget) pTarget = FindFamily(m_pRes, AF_INET);
        if (!pTarget) return;
        m_sTargetIP = ToNumeric(pTarget);
    }
    m_bOk = !m_sTargetIP.empty();
}

void CKeepNickDNSJob::runMain() {
    static_cast<CKeepNickMod*>(GetModule())->OnDNSDone(this);
}
#endif

// ------------------------- module: lifecycle -------------------------

bool CKeepNickMod::OnLoad(const CString& sArgs, CString& sMessage) {
    (void)sArgs;
    m_uInterval = GetNV("interval").ToUInt();
    if (m_uInterval < 30 || m_uInterval > 3600) m_uInterval = 30;
    m_bRotation = GetNV("rotation").ToBool();
    m_bFreeBind = GetNV("freebind").empty() || GetNV("freebind").ToBool();

    LoadNets();
    AddTimer(new CKeepNickTimer(this));
    sMessage = "Holds nicks for networks without NickServ";
    return true;
}

void CKeepNickMod::LoadNets() {
    std::vector<CString> vsKeys;
    for (MCString::iterator it = BeginNV(); it != EndNV(); ++it) {
        if (it->first.StartsWith("nicks:")) vsKeys.push_back(it->first);
    }
    for (const CString& sNVKey : vsKeys) {
        std::pair<CString, CString> pr =
            KeepNickUtils::ParseNetKey(sNVKey.substr(6));
        CUser* pUser = CZNC::Get().FindUser(pr.first);
        if (!pUser) continue;
        CIRCNetwork* pNetwork = pUser->FindNetwork(pr.second);
        if (!pNetwork) continue;
        LoadNet(KeyOf(pNetwork), pNetwork);
    }
}

void CKeepNickMod::LoadNet(const CString& sKey, CIRCNetwork* pNetwork) {
    STarget& t = m_msNets[sKey];
    t.vsNicks = KeepNickUtils::ParseNickList(GetNV("nicks:" + sKey));
    t.vsNicks.erase(std::remove_if(t.vsNicks.begin(), t.vsNicks.end(),
                                   [](const CString& s) {
                                       return !KeepNickUtils::IsValidNick(s);
                                   }),
                    t.vsNicks.end());
    CString sEnabled = GetNV("enabled:" + sKey);
    t.bEnabled = sEnabled.empty() || sEnabled.ToBool();
}

void CKeepNickMod::SaveNet(const CString& sKey, const STarget& t) {
    SetNV("nicks:" + sKey, KeepNickUtils::FormatNickList(t.vsNicks));
    SetNV("enabled:" + sKey, t.bEnabled ? "1" : "0");
}

void CKeepNickMod::ForgetNet(const CString& sKey) {
    auto it = m_msNets.find(sKey);
    if (it != m_msNets.end()) {
        DropClone(&it->second);
        m_msNets.erase(it);
    }
    ForgetPending(sKey);
    DelNV("nicks:" + sKey);
    DelNV("enabled:" + sKey);
}

void CKeepNickMod::ForgetPending(const CString& sKey) {
    auto it = m_msPending.find(PendingKey(sKey));
    if (it != m_msPending.end()) m_msPending.erase(it);
}

CIRCNetwork* CKeepNickMod::FindNet(const CString& sKey) const {
    std::pair<CString, CString> pr = KeepNickUtils::ParseNetKey(sKey);
    CUser* pUser = CZNC::Get().FindUser(pr.first);
    if (!pUser) return nullptr;
    return pUser->FindNetwork(pr.second);
}

CKeepNickMod::STarget& CKeepNickMod::NetState(const CString& sKey,
                                              CIRCNetwork* pNetwork) {
    auto it = m_msNets.find(sKey);
    if (it == m_msNets.end()) {
        LoadNet(sKey, pNetwork);
        it = m_msNets.find(sKey);
    }
    return it->second;
}

// ------------------------- module: helpers -------------------------

unsigned int CKeepNickMod::NickLenOf(const STarget& t,
                                     CIRCNetwork* pNetwork) const {
    if (t.uNickLen != 0) return t.uNickLen;
    CIRCSock* pSock = pNetwork->GetIRCSock();
    if (pSock) return pSock->GetMaxNickLen();
    return 30;
}

unsigned int CKeepNickMod::CountClones() const {
    unsigned int uCount = 0;
    for (const auto& it : m_msNets) {
        if (it.second.pClone) uCount++;
    }
    return uCount + (unsigned int)m_msPending.size();
}

void CKeepNickMod::Log(CIRCNetwork* pNetwork, const CString& sMsg) {
    DEBUG("keepnick: " << sMsg);
    if (pNetwork) {
        pNetwork->PutModule(GetModName(), sMsg);
    } else {
        PutModule(sMsg);
    }
}

void CKeepNickMod::SendTakeToUser(CIRCNetwork* pNetwork, const CString& sNick) {
    Log(pNetwork, "The nick " + sNick +
                      " is being handed to you: /nick " + sNick +
                      " now (the clone keeps it at most " +
                      CString(HANDOFF_TIMEOUT) + "s)");
}

bool CKeepNickMod::UserOwnsNick(CIRCNetwork* pNetwork,
                                const std::vector<CString>& vsNicks) {
    CIRCSock* pSock = pNetwork->GetIRCSock();
    if (!pSock || !pSock->IsAuthed()) return false;
    const CString& sNick = pSock->GetNick();
    for (const CString& s : vsNicks) {
        if (sNick.Equals(s)) return true;
    }
    return false;
}

// ------------------------- module: state machine -------------------------

void CKeepNickMod::Tick() {
    const std::map<CString, CUser*>& msUsers = CZNC::Get().GetUserMap();
    for (const auto& itu : msUsers) {
        for (CIRCNetwork* pNetwork : itu.second->GetNetworks()) {
            CString sKey =
                KeepNickUtils::NetKey(itu.first, pNetwork->GetName());
            auto it = m_msNets.find(sKey);
            if (it == m_msNets.end() && HasNV("nicks:" + sKey)) {
                LoadNet(sKey, pNetwork);
                it = m_msNets.find(sKey);
            }
            if (it != m_msNets.end()) {
                TickNet(it->second, pNetwork, sKey);
            }
        }
    }
}

void CKeepNickMod::TickNet(STarget& t, CIRCNetwork* pNetwork,
                           const CString& sKey) {
    time_t now = time(nullptr);

    if (!t.bEnabled || t.vsNicks.empty()) {
        if (t.pClone) {
            Log(pNetwork, "Dropping the clone: keepnick is disabled here");
            DropClone(&t);
        }
        ForgetPending(sKey);
        t.tHandoffDeadline = 0;
        return;
    }

    CIRCSock* pIRCSock = pNetwork->GetIRCSock();
    CString sUserNick =
        (pIRCSock && pIRCSock->IsAuthed()) ? pIRCSock->GetNick() : "";
    bool bUserWantsNick = !sUserNick.empty() &&
                          UserOwnsNick(pNetwork, t.vsNicks);

    if (t.pClone) {
        CKeepNickSock* p = t.pClone;
        if (bUserWantsNick && sUserNick.Equals(p->GetTargetNick())) {
            if (p->GetState() == CKeepNickSock::EState::Released) {
                HandoffSuccess(t, pNetwork);
                return;
            }
            if (p->GetState() == CKeepNickSock::EState::Holding) {
                BeginHandoff(t, pNetwork);
            }
        } else if (p->GetState() == CKeepNickSock::EState::Released) {
            if (t.tHandoffDeadline != 0) {
                if (now >= t.tHandoffDeadline) {
                    Log(pNetwork, "Handoff timed out, holding " +
                                      p->GetTargetNick() + " again");
                    t.tHandoffDeadline = 0;
                    p->Retake();
                }
            } else if (now >= t.tNextAttempt) {
                // Not holding the target nick and no handoff in progress
                // (e.g. a Retake was rejected): try to get back on target.
                p->Retake();
            }
        }
    } else if (now >= t.tNextAttempt) {
        if (bUserWantsNick) {
            // The user is online and already uses one of our nicks; nothing
            // to hold. Re-check later in case they go away again.
            t.tNextAttempt = now + Interval();
        } else if (pIRCSock && !pIRCSock->IsAuthed()) {
            // Don't race the real user's registration.
            t.tNextAttempt = now + 5;
        } else {
            StartClone(t, pNetwork, sKey);
        }
    }
}

void CKeepNickMod::StartClone(STarget& t, CIRCNetwork* pNetwork,
                              const CString& sKey) {
    CServer* pServer = pNetwork->GetCurrentServer();
    if (!pServer && !pNetwork->GetServers().empty()) {
        pServer = pNetwork->GetServers()[0];
    }
    if (!pServer) return;

#ifndef HAVE_LIBSSL
    if (pServer->IsSSL()) {
        Log(pNetwork, "Server " + pServer->GetName() +
                          " needs SSL, but ZNC was built without SSL support");
        t.tNextAttempt = time(nullptr) + 3600;
        return;
    }
#endif

    unsigned int uNickLen = NickLenOf(t, pNetwork);
    CString sNick;
    for (unsigned int i = 0; i < t.vsNicks.size(); i++) {
        sNick = KeepNickUtils::NextCandidate(t.vsNicks, t.uCursor, m_bRotation,
                                             uNickLen);
        if (KeepNickUtils::IsValidNick(sNick)) break;
        t.uCursor++;
        sNick = "";
    }
    if (sNick.empty()) {
        t.tNextAttempt = time(nullptr) + Interval();
        return;
    }

    if (CountClones() >= MAX_CLONES) return;
    ForgetPending(sKey);

    SPending p;
    p.sServerName = pServer->GetName();
    p.uPort = pServer->GetPort();
    p.bSSL = pServer->IsSSL();
    p.sPass = pServer->GetPass();
    p.sNick = sNick;
    m_msPending[PendingKey(sKey)] = p;

#ifdef HAVE_PTHREAD
    AddJob(new CKeepNickDNSJob(this, sKey, PendingKey(sKey), pServer->GetName(),
                               pNetwork->GetBindHost()));
#else
    m_msPending.erase(PendingKey(sKey));
    t.tNextAttempt = time(nullptr) + Interval();
#endif
}

#ifdef HAVE_PTHREAD
void CKeepNickMod::OnDNSDone(CKeepNickDNSJob* pJob) {
    auto itP = m_msPending.find(pJob->GetPendingKey());
    if (itP == m_msPending.end()) return;  // stale job
    SPending sp = itP->second;
    m_msPending.erase(itP);

    auto it = m_msNets.find(pJob->GetKey());
    if (it == m_msNets.end()) return;
    STarget& t = it->second;
    CIRCNetwork* pNetwork = FindNet(pJob->GetKey());
    if (!pNetwork) {
        m_msNets.erase(it);
        return;
    }
    if (t.pClone) return;  // a clone appeared meanwhile
    if (!t.bEnabled || t.vsNicks.empty()) return;

    if (!pJob->IsOk()) {
        AttemptFailed(t, pNetwork, false,
                      "DNS: can't resolve " + sp.sServerName);
        return;
    }

    auto pSock = new CKeepNickSock(this, pJob->GetKey(), sp.sNick,
                                   sp.sServerName, sp.uPort, sp.bSSL,
                                   sp.sPass);
    pSock->SetTargetIP(pJob->GetTargetIP());
    pSock->SetBindIP(pJob->GetBindIP());
    if (!pSock->Dial(m_bFreeBind)) {
        delete pSock;  // never entered the manager
        AttemptFailed(t, pNetwork, false,
                      "can't connect to " + pJob->GetTargetIP());
        return;
    }
    GetManager()->AddSock(pSock, pSock->SockName());
    t.pClone = pSock;
    t.tHandoffDeadline = 0;
    Log(pNetwork, "Connecting to " + pJob->GetTargetIP() + ":" +
                      CString(sp.uPort) + " as " + sp.sNick);
}
#endif

void CKeepNickMod::OnCloneEvent(ECloneEvent e, CKeepNickSock* pSock) {
    auto it = m_msNets.find(pSock->GetKey());
    if (it == m_msNets.end() || it->second.pClone != pSock) return;
    STarget& t = it->second;
    CIRCNetwork* pNetwork = FindNet(it->first);

    switch (e) {
        case ECloneEvent::Up:
            t.uFailLevel = 0;
            t.uCursor = 0;
            if (pSock->GetNickLen() != 0) t.uNickLen = pSock->GetNickLen();
            Log(pNetwork, "Holding " + pSock->GetNick() + " on " +
                              pSock->GetServerName());
            break;
        case ECloneEvent::Rejected:
            t.uCursor++;
            AttemptFailed(t, pNetwork, false,
                          pSock->GetNick() + " is not available");
            DropClone(&t);
            break;
        case ECloneEvent::NickBusy:
            // Somebody sniped the nick during a handoff or a retake; Tick()
            // retries after the backoff elapses.
            AttemptFailed(t, pNetwork, false,
                          pSock->GetTargetNick() + " was taken meanwhile");
            break;
        case ECloneEvent::NickChanged:
            if (pSock->GetState() == CKeepNickSock::EState::Holding &&
                pSock->GetNick().Equals(pSock->GetTargetNick())) {
                t.uFailLevel = 0;
                Log(pNetwork, "Holding " + pSock->GetNick() + " again");
            }
            break;
        case ECloneEvent::NickLenKnown:
            if (pSock->GetNickLen() != 0) t.uNickLen = pSock->GetNickLen();
            break;
    }
}

void CKeepNickMod::OnCloneLost(CKeepNickSock* pSock, bool bKLine) {
    auto it = m_msNets.find(pSock->GetKey());
    if (it == m_msNets.end() || it->second.pClone != pSock) {
        pSock->Detach();
        return;
    }
    STarget& t = it->second;
    t.pClone = nullptr;
    t.tHandoffDeadline = 0;
    pSock->Detach();
    CIRCNetwork* pNetwork = FindNet(it->first);
    AttemptFailed(t, pNetwork, bKLine,
                  "clone for " + pSock->GetNick() + " disconnected");
}

void CKeepNickMod::DropClone(STarget* t) {
    if (!t || !t->pClone) return;
    CKeepNickSock* pSock = t->pClone;
    t->pClone = nullptr;
    t->tHandoffDeadline = 0;
    pSock->Detach();
    GetManager()->DelSockByAddr(pSock);
}

void CKeepNickMod::AttemptFailed(STarget& t, CIRCNetwork* pNetwork,
                                 bool bKLine, const CString& sWhy) {
    t.uFailLevel++;
    unsigned int uDelay =
        bKLine ? KeepNickUtils::KLineBackoffSeconds(Interval())
               : KeepNickUtils::BackoffSeconds(Interval(), t.uFailLevel);
    t.tNextAttempt = time(nullptr) + uDelay;
    Log(pNetwork, sWhy + ", next attempt in " + CString(uDelay) + "s");
}

void CKeepNickMod::BeginHandoff(STarget& t, CIRCNetwork* pNetwork) {
    CKeepNickSock* p = t.pClone;
    if (!p || p->GetState() != CKeepNickSock::EState::Holding) return;
    if (t.tHandoffDeadline != 0) return;  // already offered

    CString sTemp =
        KeepNickUtils::TempNick(p->GetTargetNick(), NickLenOf(t, pNetwork));
    if (sTemp.empty()) {
        // The nick is so long that no temporary variant fits; drop the
        // clone entirely so the user can register with the nick.
        Log(pNetwork, "Releasing " + p->GetTargetNick() + " for you");
        HandoffSuccess(t, pNetwork);
        t.tNextAttempt = time(nullptr) + 120;
        return;
    }
    t.tHandoffDeadline = time(nullptr) + HANDOFF_TIMEOUT;
    Log(pNetwork, "Handing " + p->GetTargetNick() + " over to you");
    p->BeginHandoff(sTemp);
    SendTakeToUser(pNetwork, p->GetTargetNick());
}

void CKeepNickMod::HandoffSuccess(STarget& t, CIRCNetwork* pNetwork) {
    CString sNick = t.pClone ? t.pClone->GetTargetNick() : "";
    DropClone(&t);
    t.uFailLevel = 0;
    t.uCursor = 0;
    t.tNextAttempt = time(nullptr) + Interval();
    Log(pNetwork, "You are using " + sNick + " again");
}

// ------------------------- module: hooks -------------------------

void CKeepNickMod::OnIRCConnected() {
    CIRCNetwork* pNetwork = GetNetwork();
    if (!pNetwork) return;
    auto it = m_msNets.find(KeyOf(pNetwork));
    if (it == m_msNets.end()) return;
    STarget& t = it->second;
    if (!t.pClone) return;
    CIRCSock* pSock = pNetwork->GetIRCSock();
    if (pSock && pSock->GetNick().Equals(t.pClone->GetTargetNick())) {
        BeginHandoff(t, pNetwork);
    }
}

void CKeepNickMod::OnNickMessage(CNickMessage& Message,
                                 const std::vector<CChan*>& vChans) {
    CIRCNetwork* pNetwork = GetNetwork();
    if (!pNetwork) return;
    auto it = m_msNets.find(KeyOf(pNetwork));
    if (it == m_msNets.end()) return;
    STarget& t = it->second;
    if (!t.pClone) return;
    if (!Message.GetNewNick().Equals(t.pClone->GetTargetNick())) return;
    // React only to the user's own nick change; otherwise this is somebody
    // else on the network changing their nick. Tick() covers any races.
    CIRCSock* pSock = pNetwork->GetIRCSock();
    if (!pSock || !pSock->GetNick().Equals(Message.GetNewNick())) return;
    if (t.pClone->GetState() == CKeepNickSock::EState::Released) {
        HandoffSuccess(t, pNetwork);
    } else if (t.pClone->GetState() == CKeepNickSock::EState::Holding) {
        BeginHandoff(t, pNetwork);
    }
}

EModRet CKeepNickMod::OnNumericMessage(CNumericMessage& Message) {
    CIRCNetwork* pNetwork = GetNetwork();
    if (pNetwork && Message.GetCode() == 433) {
        CIRCSock* pSock = pNetwork->GetIRCSock();
        auto it = m_msNets.find(KeyOf(pNetwork));
        if (pSock && !pSock->IsAuthed() && it != m_msNets.end() &&
            it->second.pClone &&
            it->second.pClone->GetState() == CKeepNickSock::EState::Holding &&
            it->second.pClone->GetTargetNick().Equals(Message.GetParam(1))) {
            // The user's registration hit our clone; free the nick right
            // away so their retry can succeed.
            BeginHandoff(it->second, pNetwork);
        }
    }
    return CONTINUE;
}

EModRet CKeepNickMod::OnDeleteUser(CUser& User) {
    std::vector<CString> vsKeys;
    for (const auto& it : m_msNets) {
        if (KeepNickUtils::ParseNetKey(it.first).first.Equals(
                User.GetUserName())) {
            vsKeys.push_back(it.first);
        }
    }
    for (const CString& sKey : vsKeys) ForgetNet(sKey);
    return CONTINUE;
}

EModRet CKeepNickMod::OnDeleteNetwork(CIRCNetwork& Network) {
    ForgetNet(KeyOf(&Network));
    return CONTINUE;
}

// ------------------------- module: commands -------------------------

void CKeepNickMod::OnModCommand(const CString& sLine) {
    CUser* pUser = GetUser();
    if (!pUser || !pUser->IsAdmin()) {
        PutModule("Access denied");
        return;
    }
    CModule::OnModCommand(sLine);
}

CIRCNetwork* CKeepNickMod::NeedNetwork() {
    CIRCNetwork* pNetwork = GetNetwork();
    if (!pNetwork) {
        PutModule("This command needs a network: use it from an IRC client");
    }
    return pNetwork;
}

void CKeepNickMod::CmdAdd(const CString& sLine) {
    CIRCNetwork* pNetwork = NeedNetwork();
    if (!pNetwork) return;
    CString sNicks = sLine.Token(1, true);
    if (sNicks.empty()) {
        PutModule("Usage: Add <nick> [nick ...]");
        return;
    }
    CString sKey = KeyOf(pNetwork);
    STarget& t = NetState(sKey, pNetwork);
    VCString vsTokens;
    sNicks.Split(" ", vsTokens, false);
    unsigned int uAdded = 0;
    for (const CString& s : vsTokens) {
        if (!KeepNickUtils::IsValidNick(s)) {
            PutModule("Skipping " + s + ": not a valid nick");
            continue;
        }
        bool bDup = false;
        for (const CString& sOld : t.vsNicks) {
            if (sOld.Equals(s)) {
                bDup = true;
                break;
            }
        }
        if (!bDup) {
            t.vsNicks.push_back(s);
            uAdded++;
        }
    }
    t.bEnabled = true;
    t.tNextAttempt = 0;
    SaveNet(sKey, t);
    PutModule("Holding " + KeepNickUtils::FormatNickList(t.vsNicks) + " on " +
              pNetwork->GetName() + " (" + CString(uAdded) + " new), enabled");
}

void CKeepNickMod::CmdDel(const CString& sLine) {
    CIRCNetwork* pNetwork = NeedNetwork();
    if (!pNetwork) return;
    CString sNicks = sLine.Token(1, true);
    if (sNicks.empty()) {
        PutModule("Usage: Del <nick> [nick ...]");
        return;
    }
    CString sKey = KeyOf(pNetwork);
    auto it = m_msNets.find(sKey);
    if (it == m_msNets.end()) {
        PutModule("Nothing is being held on this network");
        return;
    }
    STarget& t = it->second;
    VCString vsTokens;
    sNicks.Split(" ", vsTokens, false);
    for (const CString& s : vsTokens) {
        auto itN = t.vsNicks.begin();
        while (itN != t.vsNicks.end()) {
            if (itN->Equals(s)) {
                itN = t.vsNicks.erase(itN);
            } else {
                ++itN;
            }
        }
    }
    SaveNet(sKey, t);
    if (t.vsNicks.empty()) {
        DropClone(&t);
        PutModule("No nicks left on " + pNetwork->GetName());
    } else {
        PutModule("Now holding " + KeepNickUtils::FormatNickList(t.vsNicks));
    }
}

void CKeepNickMod::CmdList(const CString& sLine) {
    CTable Table;
    Table.AddColumn("User/Network");
    Table.AddColumn("On");
    Table.AddColumn("Holding");
    Table.AddColumn("Nicks");
    unsigned int uRows = 0;
    for (const auto& it : m_msNets) {
        const STarget& t = it.second;
        if (t.vsNicks.empty() && !t.pClone) continue;
        Table.AddRow();
        Table.SetCell("User/Network", it.first);
        Table.SetCell("On", t.bEnabled ? "yes" : "no");
        CString sState = "-";
        if (t.pClone) {
            switch (t.pClone->GetState()) {
                case CKeepNickSock::EState::Registering:
                    sState = "connecting";
                    break;
                case CKeepNickSock::EState::Holding:
                    sState = t.pClone->GetNick();
                    break;
                case CKeepNickSock::EState::Released:
                    sState = t.pClone->GetNick() + " (handoff)";
                    break;
            }
        }
        Table.SetCell("Holding", sState);
        Table.SetCell("Nicks", KeepNickUtils::FormatNickList(t.vsNicks));
        uRows++;
    }
    if (uRows == 0) {
        PutModule("No nick lists configured. Use: Add <nick> [nick ...]");
        return;
    }
    PutModule(Table);
    PutModule("Interval: " + CString(Interval()) + "s, Rotation: " +
              (m_bRotation ? "on" : "off") + ", FreeBind: " +
              (m_bFreeBind ? "on" : "off"));
}

void CKeepNickMod::CmdOnOff(const CString& sLine, bool bOn) {
    CIRCNetwork* pNetwork = NeedNetwork();
    if (!pNetwork) return;
    CString sKey = KeyOf(pNetwork);
    STarget& t = NetState(sKey, pNetwork);
    t.bEnabled = bOn;
    SaveNet(sKey, t);
    if (!bOn) DropClone(&t);
    PutModule("Keepnick is now " + CString(bOn ? "on" : "off") + " for " +
              pNetwork->GetName());
}

void CKeepNickMod::CmdTake(const CString& sLine) {
    CIRCNetwork* pNetwork = NeedNetwork();
    if (!pNetwork) return;
    auto it = m_msNets.find(KeyOf(pNetwork));
    if (it == m_msNets.end() || !it->second.pClone) {
        PutModule("No clone is holding a nick right now");
        return;
    }
    if (it->second.pClone->GetState() !=
        CKeepNickSock::EState::Holding) {
        PutModule("The clone is still connecting; try again later");
        return;
    }
    BeginHandoff(it->second, pNetwork);
}

void CKeepNickMod::CmdInterval(const CString& sLine) {
    CString sArg = sLine.Token(1);
    if (sArg.empty()) {
        PutModule("Interval: " + CString(Interval()) + "s");
        return;
    }
    unsigned int u = sArg.ToUInt();
    if (u < 30 || u > 3600) {
        PutModule("Interval must be between 30 and 3600 seconds");
        return;
    }
    m_uInterval = u;
    SetNV("interval", CString(u));
    PutModule("Interval set to " + CString(u) + "s");
}

void CKeepNickMod::CmdRotation(const CString& sLine) {
    CString sArg = sLine.Token(1);
    if (sArg.empty()) {
        PutModule("Rotation is " + CString(m_bRotation ? "on" : "off"));
        return;
    }
    m_bRotation = sArg.ToBool();
    SetNV("rotation", m_bRotation ? "on" : "off");
    PutModule("Rotation is now " + CString(m_bRotation ? "on" : "off") +
              ": candidates are tried as nick, nick1, ... , nick9");
}

void CKeepNickMod::CmdFreeBind(const CString& sLine) {
    CString sArg = sLine.Token(1);
    if (sArg.empty()) {
        PutModule("FreeBind is " + CString(m_bFreeBind ? "on" : "off"));
        return;
    }
    m_bFreeBind = sArg.ToBool();
    SetNV("freebind", m_bFreeBind ? "on" : "off");
    PutModule("FreeBind is now " + CString(m_bFreeBind ? "on" : "off") +
              " (applies to new clones)");
}

GLOBALMODULEDEFS(CKeepNickMod,
                 "Holds your nick while you are away (for networks without "
                 "NickServ)")
