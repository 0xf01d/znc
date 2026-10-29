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

#include <gtest/gtest.h>

#include "keepnick_utils.h"

TEST(KeepNickTest, IsValidNick) {
    EXPECT_TRUE(KeepNickUtils::IsValidNick("foo"));
    EXPECT_TRUE(KeepNickUtils::IsValidNick("foo-"));
    EXPECT_TRUE(KeepNickUtils::IsValidNick("foo_"));
    EXPECT_TRUE(KeepNickUtils::IsValidNick("Foo123[bar]`^\\{|}"));
    EXPECT_FALSE(KeepNickUtils::IsValidNick(""));
    EXPECT_FALSE(KeepNickUtils::IsValidNick("1foo"));  // first char is a digit
    EXPECT_FALSE(KeepNickUtils::IsValidNick("-foo"));  // first char is '-'
    EXPECT_FALSE(KeepNickUtils::IsValidNick("fo o"));
    EXPECT_FALSE(KeepNickUtils::IsValidNick("fo@o"));
    EXPECT_FALSE(KeepNickUtils::IsValidNick("fo!o"));
}

TEST(KeepNickTest, IsValidNickLength) {
    CString sLong(64, 'a');
    EXPECT_TRUE(KeepNickUtils::IsValidNick(sLong));
    CString sTooLong(65, 'a');
    EXPECT_FALSE(KeepNickUtils::IsValidNick(sTooLong));
}

TEST(KeepNickTest, TrimNick) {
    EXPECT_EQ("foo", KeepNickUtils::TrimNick("foo", 0));
    EXPECT_EQ("foo", KeepNickUtils::TrimNick("foo", 10));
    EXPECT_EQ("foo", KeepNickUtils::TrimNick("foo", 3));
    EXPECT_EQ("fo", KeepNickUtils::TrimNick("foo", 2));
    EXPECT_EQ("f", KeepNickUtils::TrimNick("foo", 1));
}

TEST(KeepNickTest, SuffixedNick) {
    EXPECT_EQ("foo3", KeepNickUtils::SuffixedNick("foo", 3, 10));
    EXPECT_EQ("fo3", KeepNickUtils::SuffixedNick("foo", 3, 3));
    EXPECT_EQ("f3", KeepNickUtils::SuffixedNick("foo", 3, 2));
    // No room for the digit
    EXPECT_EQ("", KeepNickUtils::SuffixedNick("foo", 3, 1));
    EXPECT_EQ("", KeepNickUtils::SuffixedNick("foo", 0, 10));
    EXPECT_EQ("", KeepNickUtils::SuffixedNick("foo", 10, 10));
}

TEST(KeepNickTest, TempNick) {
    EXPECT_EQ("foo-kn", KeepNickUtils::TempNick("foo", 20));
    // Truncated to NICKLEN, but still different from the original
    EXPECT_EQ("123456789-", KeepNickUtils::TempNick("123456789", 10));
    // First variant collides after truncation, second one is used
    EXPECT_EQ("abcdef-k`", KeepNickUtils::TempNick("abcdef-kn", 9));
    // Impossible: the nick already uses the whole budget
    EXPECT_EQ("", KeepNickUtils::TempNick("a", 1));
}

TEST(KeepNickTest, BackoffSeconds) {
    EXPECT_EQ(30u, KeepNickUtils::BackoffSeconds(30, 0));
    EXPECT_EQ(60u, KeepNickUtils::BackoffSeconds(30, 1));
    EXPECT_EQ(120u, KeepNickUtils::BackoffSeconds(30, 2));
    EXPECT_EQ(240u, KeepNickUtils::BackoffSeconds(30, 3));
    // Capped at the default 3600
    EXPECT_EQ(3600u, KeepNickUtils::BackoffSeconds(30, 10));
    // Zero interval falls back to 30
    EXPECT_EQ(30u, KeepNickUtils::BackoffSeconds(0, 0));
    // Custom cap
    EXPECT_EQ(100u, KeepNickUtils::BackoffSeconds(30, 5, 100));
    // Overflow safety: huge fail level must not wrap around
    EXPECT_EQ(3600u, KeepNickUtils::BackoffSeconds(30, 1000000));
    EXPECT_EQ(3600u, KeepNickUtils::BackoffSeconds(600, 1000000));
}

TEST(KeepNickTest, KLineBackoffSeconds) {
    EXPECT_EQ(600u, KeepNickUtils::KLineBackoffSeconds(30));
    EXPECT_EQ(600u, KeepNickUtils::KLineBackoffSeconds(60));
    EXPECT_EQ(960u, KeepNickUtils::KLineBackoffSeconds(120));
    EXPECT_EQ(3600u, KeepNickUtils::KLineBackoffSeconds(600));
    EXPECT_EQ(3600u, KeepNickUtils::KLineBackoffSeconds(0));
}

TEST(KeepNickTest, RandomV6FromPool) {
    // /48: prefix kept, subnet+IID random, in-pool
    CString s1 = KeepNickUtils::RandomV6FromPool("2001:db8:aa00::/48");
    CString s2 = KeepNickUtils::RandomV6FromPool("2001:db8:aa00::/48");
    ASSERT_FALSE(s1.empty());
    EXPECT_TRUE(s1.StartsWith("2001:db8:aa"));
    EXPECT_NE(s1, s2);
    // valid parse
    in6_addr a;
    EXPECT_EQ(1, inet_pton(AF_INET6, s1.c_str(), &a));
    // /64 pool: only IID random
    CString s3 = KeepNickUtils::RandomV6FromPool("2001:db8:aa00::/64");
    ASSERT_FALSE(s3.empty());
    EXPECT_TRUE(s3.StartsWith("2001:db8:aa00:"));
    // invalid: too long prefix, bad addr
    EXPECT_TRUE(KeepNickUtils::RandomV6FromPool("2001:db8::/65").empty());
    EXPECT_TRUE(KeepNickUtils::RandomV6FromPool("nonsense/48").empty());
    EXPECT_TRUE(KeepNickUtils::RandomV6FromPool("").empty());
}
TEST(KeepNickTest, NextCandidateNoRotation) {
    std::vector<CString> vsNicks = {"foo", "bar", "baz"};
    EXPECT_EQ("foo", KeepNickUtils::NextCandidate(vsNicks, 0, false, 30));
    EXPECT_EQ("bar", KeepNickUtils::NextCandidate(vsNicks, 1, false, 30));
    EXPECT_EQ("baz", KeepNickUtils::NextCandidate(vsNicks, 2, false, 30));
    EXPECT_EQ("foo", KeepNickUtils::NextCandidate(vsNicks, 3, false, 30));
}

TEST(KeepNickTest, NextCandidateRotation) {
    std::vector<CString> vsNicks = {"foo", "bar"};
    // Cursor 0: plain first nick
    EXPECT_EQ("foo", KeepNickUtils::NextCandidate(vsNicks, 0, true, 30));
    for (unsigned int i = 1; i <= 9; i++) {
        EXPECT_EQ("foo" + CString(i),
                  KeepNickUtils::NextCandidate(vsNicks, i, true, 30));
    }
    // Cursor 10: plain second nick
    EXPECT_EQ("bar", KeepNickUtils::NextCandidate(vsNicks, 10, true, 30));
    EXPECT_EQ("bar1", KeepNickUtils::NextCandidate(vsNicks, 11, true, 30));
    // Cursor 20: wraps back to the first nick
    EXPECT_EQ("foo", KeepNickUtils::NextCandidate(vsNicks, 20, true, 30));
}

TEST(KeepNickTest, NextCandidateEmptyAndTruncation) {
    std::vector<CString> vsNicks;
    EXPECT_EQ("", KeepNickUtils::NextCandidate(vsNicks, 0, false, 30));
    std::vector<CString> vsOne = {"averylongnick"};
    EXPECT_EQ("averylo", KeepNickUtils::NextCandidate(vsOne, 0, false, 7));
    // Rotation: the plain nick is truncated for cursor 0, and the suffixed
    // variant makes room for the digit.
    EXPECT_EQ("averylo", KeepNickUtils::NextCandidate(vsOne, 0, true, 7));
    EXPECT_EQ("averyl1", KeepNickUtils::NextCandidate(vsOne, 1, true, 7));
}

TEST(KeepNickTest, NetKeyRoundtrip) {
    CString sKey = KeepNickUtils::NetKey("user", "freenode");
    EXPECT_EQ("user/freenode", sKey);
    auto pr = KeepNickUtils::ParseNetKey(sKey);
    EXPECT_EQ("user", pr.first);
    EXPECT_EQ("freenode", pr.second);
    // Network names may contain anything but '/'
    pr = KeepNickUtils::ParseNetKey(KeepNickUtils::NetKey("u", "a/b c"));
    EXPECT_EQ("u", pr.first);
    EXPECT_EQ("a/b c", pr.second);
    // No slash at all
    pr = KeepNickUtils::ParseNetKey("broken");
    EXPECT_EQ("", pr.first);
    EXPECT_EQ("", pr.second);
}

TEST(KeepNickTest, NickListRoundtrip) {
    std::vector<CString> vsNicks = {"foo", "bar", "baz"};
    CString sList = KeepNickUtils::FormatNickList(vsNicks);
    EXPECT_EQ("foo bar baz", sList);
    EXPECT_EQ(vsNicks, KeepNickUtils::ParseNickList(sList));
    EXPECT_TRUE(KeepNickUtils::ParseNickList("").empty());
    EXPECT_EQ((std::vector<CString>{"one"}),
              KeepNickUtils::ParseNickList("one"));
}
