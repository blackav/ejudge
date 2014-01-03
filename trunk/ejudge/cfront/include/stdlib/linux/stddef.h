#ifndef __RCC_LINUX_STDDEF_H__
#define __RCC_LINUX_STDDEF_H__

#if !defined NULL
#define NULL 0
#endif

#undef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#endif /* __RCC_LINUX_STDDEF_H__ */
