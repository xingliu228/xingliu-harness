import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { resolveConfigPath } from '../src/config.ts';

test('relative database paths stay anchored to the deployment env directory after npm package switches', () => {
  const root = path.resolve('/opt/dsh-passwords');
  assert.equal(resolveConfigPath('data/platform.db', root, path.join(root, 'data', 'platform.db')), path.join(root, 'data', 'platform.db'));
  assert.equal(resolveConfigPath('/var/lib/dsh/platform.db', root, path.join(root, 'data', 'platform.db')), '/var/lib/dsh/platform.db');
});
