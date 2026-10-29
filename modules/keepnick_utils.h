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

#ifndef ZNC_MOD_KEEPNICK_UTILS_H
#define ZNC_MOD_KEEPNICK_UTILS_H

#include <znc/ZNCString.h>

#include <algorithm>
#include <utility>
#include <vector>

// Pure helpers of the keepnick module. They live in this header (instead of
// the module .cpp) so that the unit tests can cover them directly.
namespace KeepNickUtils {

inline bool IsNickFirstChar(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '[' ||
           c == ']' || c == '\\' || c == '`' || c == '_' || c == '^' ||
           c == '{' || c == '|' || c == '}';
}

inline bool IsNickChar(char c) {
    return IsNickFirstChar(c) || (c >= '0' && c <= '9') || c == '-';
}

// RFC 2812 nickname, without a length limit (the caller applies NICKLEN).
inline bool IsValidNick(const CString& sNick) {
    if (sNick.empty() || sNick.length() > 64) return false;
    if (!IsNickFirstChar(sNick[0])) return false;
    for (char c : sNick) {
        if (!IsNickChar(c)) return false;
    }
    return true;
}

// Truncate to the server's NICKLEN. Every prefix of a valid nick is a valid
// nick (trailing '-' is allowed by the grammar), so plain truncation is safe.
inline CString TrimNick(const CString& sNick, unsigned int uNickLen) {
    if (uNickLen == 0) return sNick;
    return sNick.Left(uNickLen);
}

// "nick" + digit, e.g. SuffixedNick("foo", 3, 9) == "foo3". Returns "" when
// there is no room for the digit (uNickLen too small).
inline CString SuffixedNick(const CString& sNick, unsigned int uIndex,
                            unsigned int uNickLen) {
    if (uNickLen < 2 || uIndex < 1 || uIndex > 9) return "";
    return TrimNick(sNick, uNickLen - 1) + CString(uIndex);
}

// A nick that is guaranteed to be different from sNick (used to release a
// held nick during the handoff). Returns "" when the nick length limit makes
// this impossible; the caller then falls back to QUIT-based release.
inline CString TempNick(const CString& sNick, unsigned int uNickLen) {
    CString sTemp = TrimNick(sNick + "-kn", uNickLen);
    if (uNickLen >= 2 && !sTemp.Equals(sNick)) return sTemp;
    sTemp = TrimNick(sNick, uNickLen - 1) + "`";
    if (uNickLen >= 2 && !sTemp.Equals(sNick)) return sTemp;
    return "";
}

// Exponential backoff: uInterval doubled uFailLevel times, capped at
// uCapSeconds. Overflow-safe: the doubling loop stops before uDelay can
// overflow.
inline unsigned int BackoffSeconds(unsigned int uInterval,
                                   unsigned int uFailLevel,
                                   unsigned int uCapSeconds = 3600) {
    unsigned int uDelay = uInterval ? uInterval : 30;
    for (unsigned int i = 0; i < uFailLevel; i++) {
        if (uDelay >= uCapSeconds / 2) {
            uDelay = uCapSeconds;
            break;
        }
        uDelay *= 2;
    }
    return std::min(uDelay, uCapSeconds);
}

// The server replied with an error that suggests we are not welcome (e.g.
// 465 ERR_YOUREBANNEDCREEP). Back off much harder so we don't hammer it.
inline unsigned int KLineBackoffSeconds(unsigned int uInterval) {
    unsigned int uDelay = (uInterval ? uInterval : 30) * 8;
    if (uDelay < 600) uDelay = 600;
    if (uDelay > 3600) uDelay = 3600;
    return uDelay;
}

// Which nick should the clone try next. uCursor counts the rejected
// candidates so far. With bRotation == false the list is simply cycled; with
// bRotation == true each list entry is tried with numeric suffixes (nick1,
// nick2, ...) before moving to the next entry. The first candidate is always
// the plain nick. Returns "" when there is nothing reasonable left to try.
inline CString NextCandidate(const std::vector<CString>& vsNicks,
                             unsigned int uCursor, bool bRotation,
                             unsigned int uNickLen) {
    if (vsNicks.empty()) return "";
    if (!bRotation) {
        return TrimNick(vsNicks[uCursor % vsNicks.size()], uNickLen);
    }
    unsigned int uDigit = uCursor % 10;
    const CString& sBase = vsNicks[(uCursor / 10) % vsNicks.size()];
    if (uDigit == 0) return TrimNick(sBase, uNickLen);
    return SuffixedNick(sBase, uDigit, uNickLen);
}

// Key used in module nv data and in runtime maps: "<user>/<network>".
// Neither ZNC usernames nor network names may contain '/', so this is
// unambiguous.
inline CString NetKey(const CString& sUser, const CString& sNetwork) {
    return sUser + "/" + sNetwork;
}

inline std::pair<CString, CString> ParseNetKey(const CString& sKey) {
    size_t uPos = sKey.find('/');
    if (uPos == CString::npos) return {};
    return {sKey.Left(uPos), sKey.substr(uPos + 1)};
}

inline CString FormatNickList(const std::vector<CString>& vsNicks) {
    return CString(" ").Join(vsNicks.begin(), vsNicks.end());
}

inline std::vector<CString> ParseNickList(const CString& sList) {
    VCString vsTokens;
    sList.Split(" ", vsTokens, false);
    return std::vector<CString>(vsTokens.begin(), vsTokens.end());
}

}  // namespace KeepNickUtils

#endif  // ZNC_MOD_KEEPNICK_UTILS_H
