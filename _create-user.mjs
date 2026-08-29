// 临时验证脚本：直接调用 addSubUser 证明「创建用户」后端功能可用（不依赖 dsh web / key）
// 注意：config.ts 在 import 时（模块顶层）就加载 .env，必须先设 DSH_PASSWORDS_ENV_FILE 再动态 import。
process.env.DSH_PASSWORDS_ENV_FILE = '/tmp/dshpw.env';
const { loadConfig } = await import('./dist/config.js');
const { Database } = await import('./dist/db.js');
const { AuthService } = await import('./dist/auth.js');
const { createFieldCrypto } = await import('./dist/encrypt.js');

const config = loadConfig();
const crypto = createFieldCrypto(config.dbEncKey, config.setupKey);
const db = new Database(config.dbPath, crypto);
const auth = new AuthService(config, db);
try {
  const caller = { userId: 1, username: 'admin', role: 'admin' };
  await auth.addSubUser(caller, 'demo1', 'Pass#12345!abc');
  const u = db.getUserByUsername('demo1');
  if (!u) throw new Error('user not found after addSubUser');
  console.log('CREATED:', JSON.stringify({ id: u.id, username: u.username, role: u.role }));
} catch (e) {
  console.error('ERR:', e?.message || String(e));
} finally {
  db.close();
}
