# 重置密码流程的令牌泄露面

密码重置用的是长期有效的令牌，且校验后不失效。

```
auth/totp.py     TOTP 生成与校验
auth/session.py  会话存储
tests/           20 个用例，其中 4 个是红的
```

## Run

```bash
python -m pytest tests -q
```

## 现状

20 个用例里 16 绿 4 红，红的是安全用例：

| 用例 | 现状 |
|---|---|
| `test_replay_is_rejected` | 同一个验证码可以重复使用 |
| `test_session_id_rotates_after_mfa` | 完成 MFA 后会话 id 不变，存在会话固定风险 |
| `test_expired_session_rejected` | 会话过期时间没有被校验 |
| `test_compare_is_constant_time` | 比较函数直接短路，没有常量时间实现 |

审计只给了结论，没有给复现脚本。
