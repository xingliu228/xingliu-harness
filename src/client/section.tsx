// dsh-passwords 设置分区（settings.section 一级分区）。
// 在设置页左侧导航注册一个独立分区（有自己的 label），分区体 = 静态标题 +
// 描述 + 子槽卡片列表（renderSlot 渲染注册进 dsh-passwords.plugin.item 的卡片）。
// 这样 dsh-passwords 的设置不再挤在官方"插件"列表里，而是单独成区。
import { createElement as h } from 'react';

// 客户端代码由 esbuild 打包（tsconfig exclude src/client，不经过 tsc 类型检查），
// 类型只用于编辑器提示；renderSlot 的 key 在运行时是任意字符串槽位名。
interface SectionProps {
  /** 词典翻译（由注册时的 locale: 'dshpw' 声明注入） */
  t: (key: string) => string;
  /** 渲染声明的子槽（settings.section 的 children 里声明了 dsh-passwords.plugin.item） */
  renderSlot: (key: string, owner?: unknown) => unknown;
}

const CSS = `
.dshpw-section-root{display:flex;flex-direction:column;gap:10px}
.dshpw-section-heading{font-size:16px;font-weight:600;line-height:1.4;color:var(--dsw-alias-label-primary);margin:0}
.dshpw-section-lede{font-size:13px;line-height:1.5;color:var(--dsw-alias-label-tertiary);margin:0 0 4px}
.dshpw-section-cards{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:12px}
.dshpw-section-cards>li{min-width:0}
`;

if (typeof document !== 'undefined') {
  const el = document.createElement('style');
  el.textContent = CSS;
  document.head.appendChild(el);
}

export function DshPasswordsSection(props: SectionProps) {
  const { t, renderSlot } = props;
  return h(
    'div',
    { className: 'dshpw-section-root' },
    h('h2', { className: 'dshpw-section-heading', title: t('sectionTitle') }, t('sectionTitle')),
    h('p', { className: 'dshpw-section-lede', title: t('sectionDesc') }, t('sectionDesc')),
    h('ul', { className: 'dshpw-section-cards' }, renderSlot('dsh-passwords.plugin.item', {})),
  );
}
