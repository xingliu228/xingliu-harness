// dsh-passwords 全局聊天入口：注入 dsh 主界面 `shell.overlay` 槽（root 作用域，
// 帧级悬浮层，叠加在所有列之上）。
//   - 左下角圆形聊天按钮 + 右上角红色未读角标
//   - 点击弹出居中面板（四周等距留白），外层黑色雾化 + 淡入淡出动画
//   - 右上角 X 关闭；面板配色跟随 dsh 设计令牌（--dsw-alias-*）
// 数据面：/gateway/api/messages（列表/发送）。实时采用轮询（4 秒），不依赖 SSE。
import { useEffect, useRef, useState } from 'react';
import type { PropsLocale } from '@deepseek-ai/dsh-client-ui-slots';
import { CHAT_ENTRY_CHANGED_EVENT, type ChatEntryChangeDetail } from './events';

export interface ChatMessage {
  id: number;
  sender_id: number;
  sender_name: string;
  recipient_id: number | null;
  content: string;
  tags: string[];
  created_at: string;
  /** 本地乐观发送的临时消息（服务器未确认）：渲染发送中状态 */
  pending?: boolean;
}

interface Me {
  id: number;
  username: string;
  role: 'admin' | 'user';
}

const PRESET_TAGS = ['issue', 'pr', 'discussion', 'announcement', 'question'] as const;
const POLL_MS = 4000;

// ── 聊天入口悬浮钮：中键拖动可移动（left/top 定位，localStorage 持久化）──
const FAB_SIZE = 36;
const FAB_DEFAULT_BOTTOM = 116; // 原 CSS 默认 bottom
const FAB_STORAGE_KEY = 'dshpw_fab_pos';

function defaultFabPos(): { left: number; top: number } {
  const vh = typeof window !== 'undefined' ? window.innerHeight : 800;
  return { left: 14, top: Math.max(0, vh - FAB_SIZE - FAB_DEFAULT_BOTTOM) };
}

/** 标签显示：canonical key 走 i18n，旧标签兼容映射，未知标签原样回退 */
function tagDisplay(tag: string, tr: (key: string) => string): string {
  const legacy: Record<string, string> = { 讨论: 'discussion', 公告: 'announcement', 问题: 'question', PR: 'pr' };
  const key = legacy[tag] ?? tag;
  const localized = tr(`tag.${key}`);
  return localized === `tag.${key}` ? tag : localized;
}

/** 聊天错误文案：按服务端稳定 code 本地化（跟随 dsh 语言），未知 code 回退服务端文案 */
function chatErrText(
  d: { error?: string; code?: string },
  fallback: string,
  tr: (key: string) => string,
): string {
  if (d.code) {
    const key = `err.${d.code}`;
    const localized = tr(key);
    if (localized !== key && !localized.includes('{')) return localized;
  }
  return d.error ?? fallback;
}

/** 头像色板：按用户名哈希取固定色（同一个人颜色稳定） */
const AVATAR_COLORS = ['#5b8ff9', '#5ad8a6', '#f6bd16', '#e8684a', '#6dc8ec', '#9270ca', '#ff9d4d', '#269a99'];
function avatarColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  return `${hh}:${mm}`;
}

/** 力反馈：移动端真实振动（能力检测，桌面/不支持环境静默忽略）。
 *  dsh 客户端是标准浏览器壳（Chromium），navigator.vibrate 在支持的环境下可用。 */
function haptic(ms = 12): void {
  try {
    if (typeof navigator !== 'undefined' && 'vibrate' in navigator) navigator.vibrate(ms);
  } catch {
    /* 无振动能力：静默 */
  }
}

/** 游标倒退判定：返回消息中存在 id ≤ 上次游标 = 服务端数据库被重建（自增从头开始）。
 *  纯函数导出供单测；轮询循环里用它决定是否重建基线。 */
export function isCursorReset(since: number, incoming: ChatMessage[]): boolean {
  return since > 0 && incoming.some((m) => m.id <= since);
}

/** 合并新消息：去重、按 id 升序、保留最近 200 条。
 *  无新 id 时返回原引用——每 4 秒轮询返回空时若重建数组，
 *  会触发 [messages] 滚动 effect 把用户硬拽回底部（必现缺陷）。 */
export function mergeById(prev: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  if (incoming.length === 0) return prev;
  const known = new Set(prev.map((m) => m.id));
  let hasNew = false;
  for (const m of incoming) {
    if (!known.has(m.id)) {
      hasNew = true;
      break;
    }
  }
  if (!hasNew) return prev; // 无新消息：保持原引用，滚动 effect 不触发
  const map = new Map<number, ChatMessage>();
  for (const m of prev) map.set(m.id, m);
  for (const m of incoming) map.set(m.id, m);
  return [...map.values()].sort((a, b) => a.id - b.id).slice(-200);
}

/** 聊天入口 + 面板（挂在 shell.overlay 槽） */
export function ChatLauncher(props: PropsLocale<'dshpw'>) {
  const t = props.t;
  // tagDisplay 需要 (key: string) => string，而 dshpw 词典 t 是受限 key 联合类型：
  // 包一层宽松签名适配器（运行时不变）
  const tr = (key: string) => t(key as never);
  const [open, setOpen] = useState(false);
  const [closing, setClosing] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [unread, setUnread] = useState(0);
  const [shaking, setShaking] = useState(false);
  // 账号级偏好异步读取：加载期间不闪现 FAB；请求失败时默认显示，避免 API 暂时异常把聊天永久隐藏。
  const [chatEntry, setChatEntry] = useState<'loading' | 'on' | 'off'>('loading');
  // 主用户收件人选择（Discussion #6）：'broadcast' | 用户 id；子用户无需选择（服务端默认私信主用户）
  const [to, setTo] = useState<'broadcast' | number>('broadcast');
  const [contacts, setContacts] = useState<Array<{ id: number; username: string; role: string }>>([]);
  // 设置卡片事件若先于初始 fetch 返回，记录最新本页偏好，避免旧响应把刚关闭的
  // 气泡重新打开（两个 slot 组件独立挂载，存在这类微小竞态）。
  const chatEntryOverrideRef = useRef<boolean | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const lastSeenId = useRef(0);
  const openRef = useRef(false);
  const initializedRef = useRef(false);
  // 用户是否停留在列表底部（只有贴着底部时才自动滚动，向上翻历史时不被 4s 轮询拽回）
  const atBottomRef = useRef(true);
  // 关闭动画的 180ms 定时器：重开面板时取消，避免“开了又被强制关”
  const closeTimerRef = useRef<number | null>(null);
  // 发送请求期间用户可能继续编辑；失败回滚只允许覆盖未发生新编辑的草稿
  const draftRevisionRef = useRef(0);

  // ── 中键拖动 FAB：位置 state + ref（拖动用 ref 避免重挂监听器）──
  const fabPosRef = useRef(defaultFabPos());
  const [fabPos, setFabPosState] = useState(fabPosRef.current);
  const dragRef = useRef<{
    startX: number;
    startY: number;
    baseLeft: number;
    baseTop: number;
    moved: boolean;
    lastPos: { left: number; top: number } | null;
  } | null>(null);

  // 读取按用户存储的聊天入口偏好（服务端默认开启，跨设备同步），
  // 同时取子用户列表供主用户选择私信收件人（state 仅对主用户返回全量用户）。
  useEffect(() => {
    let disposed = false;
    fetch('/api/dsh-passwords/state')
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as {
          chatEnabled?: unknown;
          users?: Array<{ id: number; username: string; role: string }>;
        };
        if (disposed) return;
        const nextContacts = Array.isArray(data.users) ? data.users.filter((u) => u.role === 'user') : [];
        setContacts(nextContacts);
        setTo((prev) =>
          prev !== 'broadcast' && !nextContacts.some((contact) => contact.id === prev) ? 'broadcast' : prev,
        );
        if (chatEntryOverrideRef.current === null) {
          setChatEntry(res.ok && data.chatEnabled === false ? 'off' : 'on');
        }
      })
      .catch(() => {
        if (!disposed && chatEntryOverrideRef.current === null) setChatEntry('on');
      });
    return () => {
      disposed = true;
    };
  }, []);

  /** 收件人列表刷新：面板打开时同步（其他端删/建子用户后下拉及时更新） */
  const refreshContacts = () => {
    fetch('/api/dsh-passwords/state')
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as {
          users?: Array<{ id: number; username: string; role: string }>;
        };
        const nextContacts = Array.isArray(data.users) ? data.users.filter((u) => u.role === 'user') : [];
        setContacts(nextContacts);
        setTo((prev) =>
          prev !== 'broadcast' && !nextContacts.some((contact) => contact.id === prev) ? 'broadcast' : prev,
        );
      })
      .catch(() => {});
  };

  // 卸载时清理关闭动画定时器（组件在 180ms 动画窗口内被卸载时避免泄漏）
  useEffect(() => {
    return () => {
      if (closeTimerRef.current !== null) {
        window.clearTimeout(closeTimerRef.current);
        closeTimerRef.current = null;
      }
    };
  }, []);

  // 设置卡片与 ChatLauncher 处在不同 slot / React 树，不能靠 props 直传。
  // 偏好保存成功后立即同步当前页面：关闭时收起面板、清未读并让轮询 effect 清理，
  // 开启时重新拉取增量消息；无需刷新整个 dsh 页面。
  useEffect(() => {
    const onEntryChanged = (event: Event) => {
      const detail = (event as CustomEvent<ChatEntryChangeDetail>).detail;
      if (!detail || typeof detail.enabled !== 'boolean') return;
      chatEntryOverrideRef.current = detail.enabled;
      setChatEntry(detail.enabled ? 'on' : 'off');
      if (!detail.enabled) {
        if (closeTimerRef.current !== null) {
          window.clearTimeout(closeTimerRef.current);
          closeTimerRef.current = null;
        }
        setOpen(false);
        setClosing(false);
        setUnread(0);
        setError('');
      }
    };
    window.addEventListener(CHAT_ENTRY_CHANGED_EVENT, onEntryChanged);
    return () => window.removeEventListener(CHAT_ENTRY_CHANGED_EVENT, onEntryChanged);
  }, []);

  // 挂载时恢复持久化位置
  useEffect(() => {
    try {
      const raw = localStorage.getItem(FAB_STORAGE_KEY);
      if (raw) {
        const p = JSON.parse(raw) as { left?: unknown; top?: unknown };
        if (typeof p.left === 'number' && typeof p.top === 'number') {
          const pos = { left: p.left, top: p.top };
          fabPosRef.current = pos;
          setFabPosState(pos);
        }
      }
    } catch {
      // 损坏数据忽略，用默认位置
    }
  }, []);

  // 中键按下开始拖动（window 级监听一次挂载，拖动状态走 ref）
  useEffect(() => {
    if (chatEntry !== 'on') return;
    const onMove = (e: MouseEvent) => {
      const d = dragRef.current;
      if (!d) return;
      const dx = e.clientX - d.startX;
      const dy = e.clientY - d.startY;
      if (!d.moved && Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const next = {
        left: Math.min(Math.max(0, d.baseLeft + dx), Math.max(0, vw - FAB_SIZE)),
        top: Math.min(Math.max(0, d.baseTop + dy), Math.max(0, vh - FAB_SIZE)),
      };
      d.lastPos = next;
      fabPosRef.current = next;
      setFabPosState(next);
    };
    const onUp = () => {
      const d = dragRef.current;
      if (!d) return;
      dragRef.current = null;
      // 触发一次 re-render：dragging 由 dragRef.current !== null 在渲染时派生，
      // 不 setState 的话 mouseup 后组件停留在最后一次 mousemove 的 dragging=true，
      // FAB 的 hover 过渡动画不会恢复（直到下一次任意 state 变化，如 4 秒轮询）
      setFabPosState((p) => ({ ...p }));
      // 实际拖动过才持久化（纯点击不落盘）；未拖动视为中键点击，无副作用
      if (d.moved && d.lastPos) {
        try {
          localStorage.setItem(FAB_STORAGE_KEY, JSON.stringify(d.lastPos));
        } catch {
          // 存储不可用（隐私模式等）：位置本次会话有效即可
        }
      }
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [chatEntry]);

  const onFabMouseDown = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (e.button !== 1) return; // 仅中键
    // 阻止中键默认行为（浏览器 autoscroll 滚动模式）
    e.preventDefault();
    dragRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      baseLeft: fabPosRef.current.left,
      baseTop: fabPosRef.current.top,
      moved: false,
      lastPos: null,
    };
  };

  // 拖动进行中：禁用 hover 放大等过渡动画，避免位置跟随抖动
  const dragging = dragRef.current !== null;

  useEffect(() => {
    openRef.current = open;
    if (open) {
      setUnread(0);
      atBottomRef.current = true; // 打开面板：跳到最新（滚动由下方 effect 执行）
    }
  }, [open]);

  // 有未读时让按钮震动一下
  useEffect(() => {
    if (unread > 0) {
      setShaking(true);
      const timer = window.setTimeout(() => setShaking(false), 520);
      return () => window.clearTimeout(timer);
    }
  }, [unread]);

  // 轮询加载 + 未读统计（不依赖 SSE，消息无需刷新页面）
  // 超时链调度（非 setInterval）：支持失败退避与 in-flight 守卫，
  // 响应超过 4s 时不再重叠堆积请求。
  useEffect(() => {
    if (chatEntry !== 'on') return;
    let disposed = false;
    let inFlight = false;
    let failStreak = 0; // 连续失败次数 → 指数退避（4s → 30s 封顶）
    let timer: number | null = null;

    const load = () => {
      if (disposed || inFlight) return; // 上一轮未返回：跳过本轮，避免请求堆积
      inFlight = true;
      // 增量拉取：服务端只返回 id > since 的新消息（第一次全量拿基线），
      // 避免每 4 秒轮询都全量下载最近 300 条留言（长期挂机 = 长期无谓带宽/CPU）。
      const since = lastSeenId.current;
      const url = '/gateway/api/messages' + (since > 0 ? '?since=' + since : '');
      fetch(url)
        .then(async (res) => {
          const d = await res.json().catch(() => ({}));
          if (disposed) return;
          if (res.ok && d.ok) {
            failStreak = 0;
            const incoming = (Array.isArray(d.messages) ? d.messages : []) as ChatMessage[];
            // 服务端返回 id DESC（新在前），这里统一成旧在前、新在后
            incoming.sort((a, b) => a.id - b.id);
            const nextMe = (d.me ?? null) as Me | null;
            setMe(nextMe);
            const maxId = incoming.length > 0 ? incoming[incoming.length - 1].id : 0;
            const sinceBefore = lastSeenId.current;
            // 游标倒退（服务端 reset 信号，或返回的 id ≤ 上次游标）= 服务端数据库
            // 被重建、自增从头开始。视为新基线：替换列表、重建游标，不把整批历史
            // 算成未读（角标 99+ 的根因）。旧“连续 3 轮空响应”启发式已删除：
            // 无法与正常无消息态区分，且空响应下 isCursorReset 永远不可达。
            const cursorReset = d.reset === true || isCursorReset(sinceBefore, incoming);
            if (!cursorReset && nextMe && initializedRef.current && maxId > sinceBefore) {
              const fresh = incoming.filter(
                (m) => m.sender_id !== nextMe.id && m.id > sinceBefore,
              ).length;
              if (fresh > 0 && !openRef.current) setUnread((u) => u + fresh);
            }
            // reset 时游标直接落到新基线的 maxId（不能用 Math.max 保留旧高游标，
            // 否则 DB 重建后永远收不到新消息，直到 id 追上旧游标）
            lastSeenId.current = cursorReset ? maxId : Math.max(sinceBefore, maxId);
            initializedRef.current = true;
            setMessages((prev) => (cursorReset ? incoming : mergeById(prev, incoming)));
            setError('');
          } else if (!res.ok) {
            // HTTP 错误同样计入退避：连续 5xx/401 时拉长轮询间隔，避免失败请求风暴
            failStreak++;
            setError(chatErrText(d, t('chat.loadFailed'), tr));
          }
        })
        .catch(() => {
          if (disposed) return;
          failStreak++;
          setError(t('chat.loadFailed'));
        })
        .finally(() => {
          inFlight = false;
          if (disposed) return;
          // 失败退避：4s、8s、16s、30s 封顶；成功恢复 4s
          const delay = failStreak > 0 ? Math.min(POLL_MS * 2 ** failStreak, 30_000) : POLL_MS;
          timer = window.setTimeout(load, delay);
        });
    };

    load();
    return () => {
      disposed = true;
      if (timer !== null) window.clearTimeout(timer);
    };
  }, [chatEntry]);

  // 新消息 / 打开面板时滚动到底部（仅在用户贴着底部时自动跟随）
  useEffect(() => {
    if (open && listRef.current && atBottomRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [messages, open]);

  const onListScroll = () => {
    const el = listRef.current;
    if (!el) return;
    atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  };

  const close = () => {
    haptic();
    setClosing(true);
    if (closeTimerRef.current !== null) window.clearTimeout(closeTimerRef.current);
    closeTimerRef.current = window.setTimeout(() => {
      closeTimerRef.current = null;
      setOpen(false);
      setClosing(false);
      setError('');
    }, 180);
  };

  const openPanel = () => {
    haptic();
    // 关闭动画进行中重开：取消 pending 的 close 定时器，否则面板开了又被强制关
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
    setClosing(false);
    setOpen(true);
    setUnread(0);
    refreshContacts();
  };

  const send = () => {
    const content = draft.trim();
    // me 未加载（首轮 messages 响应未返回）时禁用发送：此时无法确定身份/收件人口径，
    // 主用户会被服务端 400、临时消息也会因 sender_id=0 渲染到错误一侧
    if (!content || busy || me === null) return;
    haptic();
    // 乐观更新：立即把临时消息放进列表（微信式即时发送手感），
    // 服务器确认后用真实消息替换；失败回滚（移除临时 + 恢复草稿 + 报错）。
    // 临时 id 用 Date.now()（远大于自增 id，不会被 mergeById 的 200 条截断丢出列表）。
    const sendRevision = draftRevisionRef.current;
    const tempId = Date.now();
    const temp: ChatMessage = {
      id: tempId,
      sender_id: me?.id ?? 0,
      sender_name: me?.username ?? '',
      recipient_id: null,
      content,
      tags,
      created_at: new Date().toISOString(),
      pending: true,
    };
    setDraft('');
    setTags([]);
    setBusy(true);
    setError('');
    setMessages((prev) => mergeById(prev, [temp]));
    atBottomRef.current = true; // 发送后强制滚到底部
    // 投递口径（Discussion #6）：主用户显式选择广播或收件人；
    // 子用户不携带收件人字段，服务端默认私信主用户。
    const payload: Record<string, unknown> = { content, tags };
    if (me?.role === 'admin') {
      if (to === 'broadcast') payload.broadcast = true;
      else payload.recipientId = to;
    }
    fetch('/gateway/api/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(async (res) => {
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.ok) {
          const m = (d.message ?? null) as ChatMessage | null;
          setMessages((prev) => {
            const base = prev.filter((p) => p.id !== tempId);
            return m ? mergeById(base, [m]) : base;
          });
        } else {
          setMessages((prev) => prev.filter((p) => p.id !== tempId));
          if (draftRevisionRef.current === sendRevision) {
            setDraft(content);
            setTags(tags);
          }
          setError(chatErrText(d, t('chat.sendFailed'), tr));
        }
      })
      .catch(() => {
        setMessages((prev) => prev.filter((p) => p.id !== tempId));
        if (draftRevisionRef.current === sendRevision) {
          setDraft(content);
          setTags(tags);
        }
        setError(t('chat.sendFailed'));
      })
      .finally(() => setBusy(false));
  };

  const toggleTag = (tag: string) => {
    haptic();
    draftRevisionRef.current += 1;
    setTags((prev) => (prev.includes(tag) ? prev.filter((x) => x !== tag) : [...prev, tag]));
  };

  // 偏好关闭时不渲染 FAB/面板；轮询 effect 同步停用（不留后台请求或未读计数）。
  if (chatEntry !== 'on') return null;

  return (
    <>
      <button
        type="button"
        className={'dshpw-chat-fab' + (shaking ? ' shaking' : '') + (dragging ? ' dragging' : '')}
        style={{ left: fabPos.left, top: fabPos.top, bottom: 'auto' }}
        aria-label={t('chat.open')}
        title={`${t('chat.open')} · ${t('chat.dragHint')}`}
        onClick={openPanel}
        onMouseDown={onFabMouseDown}
        onAuxClick={(e) => {
          if (e.button === 1) e.preventDefault();
        }}
      >
        <span className="dshpw-chat-fab-inner">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M4 6a3 3 0 0 1 3-3h10a3 3 0 0 1 3 3v7a3 3 0 0 1-3 3H9l-4 4v-4H7a3 3 0 0 1-3-3V6z"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinejoin="round"
            />
          </svg>
          {unread > 0 && (
            <span className="dshpw-chat-badge" key={unread}>
              {unread > 99 ? '99+' : String(unread)}
            </span>
          )}
        </span>
      </button>

      {open && (
        <div
          className={'dshpw-chat-backdrop' + (closing ? ' closing' : '')}
          onClick={close}
          role="dialog"
          aria-modal="true"
          aria-label={t('chat.title')}
        >
          <div className={'dshpw-chat-panel' + (closing ? ' closing' : '')} onClick={(e) => e.stopPropagation()}>
            <div className="dshpw-chat-header">
              <span className="dshpw-chat-title">{t('chat.title')}</span>
              <button type="button" className="dshpw-chat-close" aria-label={t('chat.close')} onClick={close}>
                ×
              </button>
            </div>

            <div className="dshpw-chat-list" ref={listRef} onScroll={onListScroll}>
              {messages.length === 0 && <div className="dshpw-chat-empty">{t('chat.empty')}</div>}
              {messages.map((m) => {
                const mine = me ? m.sender_id === me.id : false;
                const name = mine ? t('chat.you') : m.sender_name;
                // 头像首字母：自己用登录用户名，对方用 sender_name
                const avatarName = mine ? me?.username || name : m.sender_name;
                const initial = (avatarName || '?').trim().slice(0, 1).toUpperCase();
                return (
                  <div
                    key={m.id}
                    className={'dshpw-chat-msg' + (mine ? ' mine' : '') + (m.pending ? ' pending' : '')}
                  >
                    {/* 微信式头像：对方按名字哈希取色，自己用品牌色（CSS 默认，不写内联） */}
                    <div
                      className="dshpw-chat-avatar"
                      style={mine ? undefined : { background: avatarColor(m.sender_name) }}
                    >
                      {initial}
                    </div>
                    {/* 昵称+时间在气泡外（微信式）：自己消息只显示时间、不显示昵称 */}
                    <div className="dshpw-chat-main">
                      <div className="dshpw-chat-meta">
                        {!mine && <span className="dshpw-chat-author">{name}</span>}
                        <span className="dshpw-chat-time">{fmtTime(m.created_at)}</span>
                      </div>
                      <div className="dshpw-chat-bubble">
                        <div className="dshpw-chat-content">{m.content}</div>
                        {m.tags.length > 0 && (
                          <div className="dshpw-chat-tags">
                            {m.tags.map((tag) => (
                              <span className="dshpw-chat-tag" key={tag}>
                                {tagDisplay(tag, tr)}
                              </span>
                            ))}
                          </div>
                        )}
                        {m.pending && (
                          <span className="dshpw-chat-pending" aria-label={t('chat.sending')}>
                            <i />
                            <i />
                            <i />
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="dshpw-chat-composer">
              <div className="dshpw-chat-tags">
                {PRESET_TAGS.map((tag) => (
                  <button
                    type="button"
                    key={tag}
                    className={'dshpw-chat-tagbtn' + (tags.includes(tag) ? ' active' : '')}
                    onClick={() => toggleTag(tag)}
                  >
                    {tagDisplay(tag, tr)}
                  </button>
                ))}
              </div>
              {me?.role === 'admin' && (
                <div className="dshpw-chat-to">
                  <span className="dshpw-chat-to-label">{t('chat.to')}</span>
                  <select
                    className="dshpw-chat-to-select"
                    value={to === 'broadcast' ? 'broadcast' : String(to)}
                    aria-label={t('chat.to')}
                    onChange={(e) =>
                      setTo(e.target.value === 'broadcast' ? 'broadcast' : Number(e.target.value))
                    }
                  >
                    <option value="broadcast">{t('chat.toBroadcast')}</option>
                    {contacts.map((c) => (
                      <option key={c.id} value={String(c.id)}>
                        {c.username}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div className="dshpw-chat-inputrow">
                <input
                  className="dshpw-chat-input"
                  value={draft}
                  placeholder={t('chat.placeholder')}
                  autoComplete="off"
                  name="dshpw-chat-draft"
                  onChange={(e) => {
                    draftRevisionRef.current += 1;
                    setDraft(e.target.value);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      send();
                    }
                  }}
                />
                <button
                  type="button"
                  className="dshpw-chat-send"
                  disabled={busy || !draft.trim() || me === null}
                  onClick={send}
                  aria-label={t('chat.send')}
                  title={t('chat.send')}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" fill="currentColor" />
                  </svg>
                </button>
              </div>
              {error && <div className="dshpw-chat-error">{error}</div>}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── 聊天面板样式：跟随 dsh 设计令牌，主题自动适配 ───────────────
const CHAT_CSS = `
.dshpw-chat-fab{position:fixed;z-index:2147483000;width:36px;height:36px;border-radius:50%;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);display:flex;align-items:center;justify-content:center;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.18);transition:transform .18s,box-shadow .18s,background .18s;pointer-events:auto;animation:dshpwFabIn .4s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-fab.dragging{transition:none;cursor:grabbing;opacity:.85}
.dshpw-chat-fab:hover{transform:scale(1.05);background:var(--dsw-alias-interactive-bg-hover);box-shadow:0 4px 12px rgba(0,0,0,.25)}
.dshpw-chat-fab:active{transform:scale(.88)}
.dshpw-chat-fab:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}
.dshpw-chat-fab.shaking{animation:dshpwShake .5s ease}
.dshpw-chat-fab-inner{position:relative;display:flex}
.dshpw-chat-badge{position:absolute;top:-12px;right:-9px;min-width:16px;height:16px;padding:0 4px;border-radius:999px;background:#ef4444;color:#fff;font-size:10px;line-height:16px;text-align:center;font-weight:600;box-shadow:0 0 0 2px var(--dsw-alias-bg-layer-2);animation:dshpwBadgePop .3s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-backdrop{position:fixed;inset:0;z-index:2147482990;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.55);backdrop-filter:blur(10px) saturate(.9);-webkit-backdrop-filter:blur(10px) saturate(.9);animation:dshpwChatFadeIn .2s ease;transition:opacity .18s ease}
.dshpw-chat-backdrop.closing{opacity:0;pointer-events:none}
.dshpw-chat-panel{display:flex;flex-direction:column;width:min(680px,calc(100vw - 48px));height:min(640px,calc(100vh - 96px));border:1px solid var(--dsw-alias-border-l2);border-radius:16px;background:var(--dsw-alias-bg-layer-2);box-shadow:0 24px 60px rgba(0,0,0,.5);overflow:hidden;animation:dshpwChatPanelIn .28s cubic-bezier(.34,1.56,.64,1);transition:opacity .18s ease,transform .18s ease}
.dshpw-chat-panel.closing{opacity:0;transform:translateY(10px) scale(.98)}
.dshpw-chat-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--dsw-alias-border-l2)}
.dshpw-chat-title{font-size:15px;font-weight:600;color:var(--dsw-alias-label-primary)}
.dshpw-chat-close{width:28px;height:28px;border:0;border-radius:8px;background:none;color:var(--dsw-alias-label-tertiary);font-size:20px;line-height:1;cursor:pointer;transition:background .15s,color .15s,transform .15s}
.dshpw-chat-close:hover{background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);transform:rotate(90deg)}
.dshpw-chat-close:active{transform:scale(.85) rotate(45deg)}
/* 微信式消息列表：浅灰底、头像+气泡两列 */
.dshpw-chat-list{flex:1;overflow-y:auto;padding:14px 14px 16px;display:flex;flex-direction:column;gap:12px;background:var(--dsw-alias-bg-layer-1);scrollbar-width:thin;scrollbar-color:var(--dsw-alias-border-l2) transparent}
.dshpw-chat-list::-webkit-scrollbar{width:8px}
.dshpw-chat-list::-webkit-scrollbar-thumb{background:var(--dsw-alias-border-l2);border-radius:999px}
.dshpw-chat-list::-webkit-scrollbar-thumb:hover{background:var(--dsw-alias-label-tertiary)}
.dshpw-chat-empty{color:var(--dsw-alias-label-tertiary);font-size:13px;text-align:center;margin:auto;display:flex;flex-direction:column;align-items:center;gap:8px}
.dshpw-chat-empty::before{content:'';width:40px;height:40px;border-radius:50%;background:var(--dsw-alias-bg-layer-3);border:1px solid var(--dsw-alias-border-l2);background-image:radial-gradient(circle at 30% 38%,var(--dsw-alias-label-tertiary) 1.5px,transparent 1.6px),radial-gradient(circle at 50% 38%,var(--dsw-alias-label-tertiary) 1.5px,transparent 1.6px),radial-gradient(circle at 70% 38%,var(--dsw-alias-label-tertiary) 1.5px,transparent 1.6px);opacity:.6}
.dshpw-chat-msg{display:flex;gap:8px;align-items:flex-start;max-width:100%;animation:dshpwMsgIn .32s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-msg.mine{flex-direction:row-reverse;animation:dshpwMsgMineIn .32s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-avatar{flex-shrink:0;width:32px;height:32px;border-radius:50%;background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary-inverted,#fff);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;user-select:none;box-shadow:0 1px 3px rgba(0,0,0,.15);transition:transform .18s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-msg:hover .dshpw-chat-avatar{transform:scale(1.08)}
/* 昵称+时间在气泡外（微信式）：内容列 = meta + 气泡 */
.dshpw-chat-main{display:flex;flex-direction:column;gap:4px;align-items:flex-start;max-width:min(78%,calc(100% - 44px));min-width:0}
.dshpw-chat-msg.mine .dshpw-chat-main{align-items:flex-end}
.dshpw-chat-bubble{position:relative;max-width:100%;padding:8px 12px;border-radius:12px;border-top-left-radius:4px;background:var(--dsw-alias-bg-layer-3);border:1px solid var(--dsw-alias-border-l2);box-shadow:0 1px 2px rgba(0,0,0,.06)}
.dshpw-chat-msg.mine .dshpw-chat-bubble{border-radius:12px;border-top-right-radius:4px;background:var(--dsw-alias-brand-primary);border-color:transparent;box-shadow:0 1px 3px rgba(0,0,0,.12)}
.dshpw-chat-msg.pending .dshpw-chat-bubble{opacity:.92}
/* 微信式小尾巴：旋转 45° 的小方块，颜色随气泡 */
.dshpw-chat-bubble::before{content:'';position:absolute;top:9px;left:-5px;width:9px;height:9px;transform:rotate(45deg);background:inherit;border-left:1px solid var(--dsw-alias-border-l2);border-bottom:1px solid var(--dsw-alias-border-l2);border-top:0;border-right:0}
.dshpw-chat-msg.mine .dshpw-chat-bubble::before{left:auto;right:-5px;border-left:0;border-bottom:0;border-top:0;border-right:0}
.dshpw-chat-meta{display:flex;align-items:baseline;gap:6px;padding:0 2px}
.dshpw-chat-author{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}
.dshpw-chat-time{font-size:11px;color:var(--dsw-alias-label-tertiary)}
.dshpw-chat-content{font-size:13px;line-height:1.5;color:var(--dsw-alias-label-primary);white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere}
.dshpw-chat-msg.mine .dshpw-chat-content{color:var(--dsw-alias-label-primary-inverted,#fff)}
.dshpw-chat-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.dshpw-chat-tag{font-size:11px;padding:1px 8px;border-radius:999px;border:1px solid var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary)}
.dshpw-chat-msg.mine .dshpw-chat-tag{border-color:color-mix(in srgb,var(--dsw-alias-label-primary-inverted,#fff) 45%,transparent);color:var(--dsw-alias-label-primary-inverted,#fff)}
/* 发送中三点跳动 */
.dshpw-chat-pending{display:inline-flex;gap:3px;align-items:center;margin-top:6px;height:6px}
.dshpw-chat-pending i{width:5px;height:5px;border-radius:50%;background:var(--dsw-alias-label-tertiary);animation:dshpwPendingBounce .9s ease-in-out infinite}
.dshpw-chat-msg.mine .dshpw-chat-pending i{background:color-mix(in srgb,var(--dsw-alias-label-primary-inverted,#fff) 70%,transparent)}
.dshpw-chat-pending i:nth-child(2){animation-delay:.15s}
.dshpw-chat-pending i:nth-child(3){animation-delay:.3s}
.dshpw-chat-composer{border-top:1px solid var(--dsw-alias-border-l2);padding:10px 12px;display:flex;flex-direction:column;gap:8px;background:var(--dsw-alias-bg-layer-2)}
.dshpw-chat-tagbtn{appearance:none;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;padding:3px 10px;font-size:11px;background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-secondary);cursor:pointer;transition:border-color .15s,color .15s,background .15s,transform .2s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-tagbtn:hover{transform:translateY(-1px)}
.dshpw-chat-tagbtn:active{transform:scale(.85)}
.dshpw-chat-tagbtn.active{border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary);background:color-mix(in srgb,var(--dsw-alias-brand-primary) 12%,transparent);animation:dshpwTagPop .3s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-inputrow{display:flex;gap:8px;align-items:center}
.dshpw-chat-input{flex:1;box-sizing:border-box;min-width:0;padding:9px 14px;font-size:13px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-3);border:1px solid var(--dsw-alias-border-l2);border-radius:18px;outline:none;transition:border-color .15s,box-shadow .15s}
.dshpw-chat-input:focus{border-color:var(--dsw-alias-brand-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--dsw-alias-brand-primary) 18%,transparent)}
.dshpw-chat-to{display:flex;align-items:center;gap:8px}
.dshpw-chat-to-label{font-size:12px;color:var(--dsw-alias-label-tertiary);flex-shrink:0}
.dshpw-chat-to-select{flex:1;min-width:0;height:30px;padding:0 8px;border-radius:8px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);font-size:13px;outline:none;cursor:pointer;transition:border-color .15s}
.dshpw-chat-to-select:focus{border-color:var(--dsw-alias-brand-primary)}
/* 圆形纸飞机发送按钮 */
.dshpw-chat-send{appearance:none;border:0;width:34px;height:34px;flex-shrink:0;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary-inverted,#fff);cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,.15);transition:transform .2s cubic-bezier(.34,1.56,.64,1),filter .15s,opacity .15s,box-shadow .15s}
.dshpw-chat-send svg{display:block;transition:transform .2s cubic-bezier(.34,1.56,.64,1)}
.dshpw-chat-send:hover:not(:disabled){transform:scale(1.08) rotate(-8deg);filter:brightness(1.06);box-shadow:0 4px 10px rgba(0,0,0,.2)}
.dshpw-chat-send:active:not(:disabled){transform:scale(.8)}
.dshpw-chat-send:active:not(:disabled) svg{transform:translateX(1px) scale(.9)}
.dshpw-chat-send:disabled{opacity:.35;cursor:default;box-shadow:none}
.dshpw-chat-error{font-size:12px;color:var(--dsw-alias-state-error-primary,#ef4444);animation:dshpwErrIn .22s ease}
@keyframes dshpwFabIn{from{opacity:0;transform:scale(0) rotate(-90deg)}to{opacity:1;transform:none}}
@keyframes dshpwChatFadeIn{from{opacity:0}to{opacity:1}}
@keyframes dshpwChatPanelIn{from{opacity:0;transform:translateY(14px) scale(.96)}to{opacity:1;transform:none}}
@keyframes dshpwMsgIn{from{opacity:0;transform:translateX(-14px) scale(.97)}to{opacity:1;transform:none}}
@keyframes dshpwMsgMineIn{from{opacity:0;transform:translateX(14px) scale(.97)}to{opacity:1;transform:none}}
@keyframes dshpwPendingBounce{0%,80%,100%{transform:translateY(0);opacity:.4}40%{transform:translateY(-3px);opacity:1}}
@keyframes dshpwBadgePop{from{transform:scale(.3);opacity:0}60%{transform:scale(1.25)}to{transform:scale(1);opacity:1}}
@keyframes dshpwTagPop{0%{transform:scale(1)}50%{transform:scale(1.18)}100%{transform:scale(1)}}
@keyframes dshpwErrIn{from{opacity:0;transform:translateY(-3px)}to{opacity:1;transform:none}}
@keyframes dshpwShake{0%,100%{transform:translateX(0)}20%{transform:translateX(-4px)}40%{transform:translateX(4px)}60%{transform:translateX(-3px)}80%{transform:translateX(3px)}}
@media (prefers-reduced-motion:reduce){.dshpw-chat-fab,.dshpw-chat-panel,.dshpw-chat-backdrop,.dshpw-chat-msg,.dshpw-chat-badge,.dshpw-chat-pending i,.dshpw-chat-send,.dshpw-chat-tagbtn,.dshpw-chat-avatar,.dshpw-chat-close,.dshpw-chat-error{animation:none!important;transition:none!important}}
`;

if (typeof document !== 'undefined') {
  const el = document.createElement('style');
  el.textContent = CHAT_CSS;
  document.head.appendChild(el);
}
