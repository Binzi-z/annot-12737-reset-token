# 重置密码流程的令牌泄露面

密码重置用的是长期有效的令牌，且校验后不失效。

```
auth/totp.py            TOTP 生成与校验（单次消费 + 常量时间比较）
auth/session.py         会话存储（TTL 强制 + MFA 后轮换 id）
auth/replay_detector.py 令牌使用序列的重放/过期/会话固定检测器
tests/                  用例，全部通过
```

## Run

```bash
python -m pytest tests -q
```

## 现状

全部用例转绿，原先四个红色安全用例的修复：

| 用例 | 修复 |
|---|---|
| `test_replay_is_rejected` | `verify` 记住已消费的计数器，同一验证码第二次出现即拒绝 |
| `test_session_id_rotates_after_mfa` | `mark_mfa` 签发全新会话 id，旧 id 不再承载认证态 |
| `test_expired_session_rejected` | `get` 强制 1 小时 TTL，过期记录直接删除并抛 `KeyError` |
| `test_compare_is_constant_time` | 比较走 `hmac.compare_digest`，新增 `compare_constant_time` |

`tests/test_replay_detector.py` 中检测器的判定与上述红色用例一一对应，并覆盖合法序列零误报。

