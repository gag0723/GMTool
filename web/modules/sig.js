/* 电子签章校验（PDF / OFD） + 时间戳解析与验证（RFC 3161 / GB/T 33000-2014） */
(function () {
  'use strict';
  const el = CB.el;

  /* ---------------- 内嵌测试夹具（base64，仅用于示例按钮/自动化采样） ---------------- */
  const SAMPLE_PDF_B64 = 'JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgKHB5cGRmKQo+PgplbmRvYmoKMiAwIG9iago8PAovVHlwZSAvUGFnZXMKL0NvdW50IDEKL0tpZHMgWyA0IDAgUiBdCj4+CmVuZG9iagozIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAyIDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovVHlwZSAvUGFnZQovUmVzb3VyY2VzIDw8Cj4+Ci9NZWRpYUJveCBbIDAuMCAwLjAgNTk1IDg0MiBdCi9QYXJlbnQgMiAwIFIKPj4KZW5kb2JqCnhyZWYKMCA1CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAxNSAwMDAwMCBuIAowMDAwMDAwMDU0IDAwMDAwIG4gCjAwMDAwMDAxMTMgMDAwMDAgbiAKMDAwMDAwMDE2MiAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDUKL1Jvb3QgMyAwIFIKL0luZm8gMSAwIFIKPj4Kc3RhcnR4cmVmCjI1NgolJUVPRgoxIDAgb2JqCjw8Ci9Qcm9kdWNlciAocHlwZGZcMDczIHB5SGFua28gMFwwNTYzOFwwNTYwKQovTW9kRGF0ZSAoRFwwNzIyMDI2MTEwMTEyMDQyNlwwNTMwOFwwNDcwMFwwNDcpCj4+CmVuZG9iagozIDAgb2JqCjw8Ci9UeXBlIC9DYXRhbG9nCi9QYWdlcyAyIDAgUgovVmVyc2lvbiAvMS43Ci9BY3JvRm9ybSA2IDAgUgo+PgplbmRvYmoKNCAwIG9iago8PAovVHlwZSAvUGFnZQovUmVzb3VyY2VzIDw8Cj4+Ci9NZWRpYUJveCBbIDAgMCA1OTUgODQyIF0KL1BhcmVudCAyIDAgUgovQW5ub3RzIFsgNyAwIFIgXQo+PgplbmRvYmoKNiAwIG9iago8PAovRmllbGRzIFsgNyAwIFIgXQovU2lnRmxhZ3MgMwo+PgplbmRvYmoKNyAwIG9iago8PAovRlQgL1NpZwovVCAoU2lnbmF0dXJlMSkKL1R5cGUgL0Fubm90Ci9TdWJ0eXBlIC9XaWRnZXQKL0YgMTMyCi9SZWN0IFsgMCAwIDAgMCBdCi9QIDQgMCBSCi9WIDggMCBSCj4+CmVuZG9iago4IDAgb2JqCjw8Ci9Db250ZW50cyA8MzA4MjBEMTgwNjA5MkE4NjQ4ODZGNzBEMDEwNzAyQTA4MjBEMDkzMDgyMEQwNTAyMDEwMTMxMEYzMDBEMDYwOTYwODY0ODAxNjUwMzA0MDIwMTA1MDAzMDBCMDYwOTJBODY0ODg2RjcwRDAxMDcwMUEwODIwNkVFMzA4MjAzNzMzMDgyMDI1QkEwMDMwMjAxMDIwMjE0NUI3QUY3QTA0RUQwM0JGMjU3Qzk2NUVFQjg2MEMyMEQ2OURDMEREQTMwMEQwNjA5MkE4NjQ4ODZGNzBEMDEwMTBCMDUwMDMwNTgzMTBCMzAwOTA2MDM1NTA0MDYxMzAyNDM0RTMxMjUzMDIzMDYwMzU1MDQwQTBDMUM0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU2OUM4OUU5OTk5MEU1ODVBQ0U1OEZCODMxMjIzMDIwMDYwMzU1MDQwMzBDMTk0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU3QURCRUU3QUJBMEU4ODA4NTMwMUUxNzBEMzIzNDMwMzEzMDMxMzAzMDMwMzAzMDMwNUExNzBEMzMzNjMwMzEzMDMxMzAzMDMwMzAzMDMwNUEzMDU4MzEwQjMwMDkwNjAzNTUwNDA2MTMwMjQzNEUzMTI1MzAyMzA2MDM1NTA0MEEwQzFDNDM2OTcwNjg2NTcyNDI2Rjc4MjBFNkI1OEJFOEFGOTVFNjlDODlFOTk5OTBFNTg1QUNFNThGQjgzMTIyMzAyMDA2MDM1NTA0MDMwQzE5NDM2OTcwNjg2NTcyNDI2Rjc4MjBFNkI1OEJFOEFGOTVFN0FEQkVFN0FCQTBFODgwODUzMDgyMDEyMjMwMEQwNjA5MkE4NjQ4ODZGNzBEMDEwMTAxMDUwMDAzODIwMTBGMDAzMDgyMDEwQTAyODIwMTAxMDBBNzYwMjIyRDZEODEyNDdGMDZCQTI2MzRCNUE2N0U3MjQ3MTRGNjk2MUE2NEYxREFDQjI2NTg5NDA0QjcxMTk5REQ4MTlBQjkxNEI1MjRGM0UxNDZFRkFCNTNDRjgwQUNFNEY0RUMxNENBMzFCRENFQkM3MTEwNjI0MDcyRUYzOTBEMjMyOTlBRkY1QzY0OTc3QTJCNzA5RTkwOUY0RDRGMjEzQTE3OURFQ0ZDMkI2N0VFRTI0QkYxNTczMDNEQjY2MkE3MzcwNzUzNEZBRkJBMjhGRTcyREREMTMzRTc5M0M4QkZEQTdBNjBBRkFENTgxRUE3MUVBQjFGOEYyREMyQ0M0NjdEOTVFQTcyNDlBMENDNEI5RTQ5MzZCNDM2RDVBMEE0NTEwMUZENjY0QUVDQTFFRDVDNjQ0ODE1MDk0Qzk3NEFFODZEOTk5MUE4RUEyMDM1MkNGQ0E5NDkwMDkxNDZGREQzNzJBODlFOTQ0QkMxOUFDOTI2QjlGNDE5REQzQ0RBQUYyNjBFNzAyOTBDMDZFMzQ4RkM1NEZGMzE0M0E1OTk4NTI1ODcwQkEwQjY1NjgxMUQ1NjU0MzFBMzdEN0I1MkE5OTY4ODJBQTA0NjdGMzM3N0JEODQ1MTg5QUU5RkZCMDRFQ0U2M0Y3NTc4RkE5NkY0QzMxM0E2RDg2MTAyMDMwMTAwMDFBMzM1MzAzMzMwMEMwNjAzNTUxRDEzMDEwMUZGMDQwMjMwMDAzMDBFMDYwMzU1MUQwRjAxMDFGRjA0MDQwMzAyMDVFMDMwMTMwNjAzNTUxRDI1MDQwQzMwMEEwNjA4MkIwNjAxMDUwNTA3MDMwMzMwMEQwNjA5MkE4NjQ4ODZGNzBEMDEwMTBCMDUwMDAzODIwMTAxMDA2QzZEOUMyQzE5NkM4NzhGOTM5QUQzQzgxN0M1RjIyOUVCRjFCQUQzRjk4RTREOUI0QzNGMzgzMkI2NjIyMzBGNzU4RkNGRjU4MTIwMkQwQzc4QUJEMDAxRDlCMEFEQTBFQ0MzNUU2QTkxNURDODgzMDU0QzcwOTg4OTdBODZDMzUyOTYzRkE2MTVGRkFCNkUwMDA0NDIyMjJBNjAwMDZCMDZGNkY2N0VBQjI4N0M4NzYyMDVGMDc4ODdBNUQ1QUEyMDA1NzRDMDk2NkY5RjVDODU2N0NGMjJFQTRGQzlGQzc4NDhFNjNCNDkwMThDMDQ4MkVGOEI3NTdFNUM2QUQxRTlFQTc2NDM0MTI5RDMxNTQ4QjNGRkJFNkRCOUE4ODNBN0JEN0Y5QkVFMDExOTU5MjM1NDg4QTBENkM1N0JGRUExRDc4OTk3MkVEQTU0MUM0QkE2Q0M2Njk0NjE3RkVCN0E0NDA0MjU4NUVGNjZDQjU0Mjg1NzcyNDZGNDk5MEJBOTAyRTQ1RkE2NDg2NkUzQkIwQzAxNUFDRDA1OEY0ODhBOEYyM0E2RkQ0QjFDQjE5NjE3MDc4MzM0M0U1NTg3NkFGOEQ3NUZEM0YyRjZEN0M5REFBODk2MDNERkJBRUJDRThCMkQxMzZDMDQ0MzIyM0NCQjBEREE3RTY4ODMzQjMwODIwMzczMzA4MjAyNUJBMDAzMDIwMTAyMDIxNDVCN0FGN0EwNEVEMDNCRjI1N0M5NjVFRUI4NjBDMjBENjlEQzBEREEzMDBEMDYwOTJBODY0ODg2RjcwRDAxMDEwQjA1MDAzMDU4MzEwQjMwMDkwNjAzNTUwNDA2MTMwMjQzNEUzMTI1MzAyMzA2MDM1NTA0MEEwQzFDNDM2OTcwNjg2NTcyNDI2Rjc4MjBFNkI1OEJFOEFGOTVFNjlDODlFOTk5OTBFNTg1QUNFNThGQjgzMTIyMzAyMDA2MDM1NTA0MDMwQzE5NDM2OTcwNjg2NTcyNDI2Rjc4MjBFNkI1OEJFOEFGOTVFN0FEQkVFN0FCQTBFODgwODUzMDFFMTcwRDMyMzQzMDMxMzAzMTMwMzAzMDMwMzAzMDVBMTcwRDMzMzYzMDMxMzAzMTMwMzAzMDMwMzAzMDVBMzA1ODMxMEIzMDA5MDYwMzU1MDQwNjEzMDI0MzRFMzEyNTMwMjMwNjAzNTUwNDBBMEMxQzQzNjk3MDY4NjU3MjQyNkY3ODIwRTZCNThCRThBRjk1RTY5Qzg5RTk5OTkwRTU4NUFDRTU4RkI4MzEyMjMwMjAwNjAzNTUwNDAzMEMxOTQzNjk3MDY4NjU3MjQyNkY3ODIwRTZCNThCRThBRjk1RTdBREJFRTdBQkEwRTg4MDg1MzA4MjAxMjIzMDBEMDYwOTJBODY0ODg2RjcwRDAxMDEwMTA1MDAwMzgyMDEwRjAwMzA4MjAxMEEwMjgyMDEwMTAwQTc2MDIyMkQ2RDgxMjQ3RjA2QkEyNjM0QjVBNjdFNzI0NzE0RjY5NjFBNjRGMURBQ0IyNjU4OTQwNEI3MTE5OUREODE5QUI5MTRCNTI0RjNFMTQ2RUZBQjUzQ0Y4MEFDRTRGNEVDMTRDQTMxQkRDRUJDNzExMDYyNDA3MkVGMzkwRDIzMjk5QUZGNUM2NDk3N0EyQjcwOUU5MDlGNEQ0RjIxM0ExNzlERUNGQzJCNjdFRUUyNEJGMTU3MzAzREI2NjJBNzM3MDc1MzRGQUZCQTI4RkU3MkRERDEzM0U3OTNDOEJGREE3QTYwQUZBRDU4MUVBNzFFQUIxRjhGMkRDMkNDNDY3RDk1RUE3MjQ5QTBDQzRCOUU0OTM2QjQzNkQ1QTBBNDUxMDFGRDY2NEFFQ0ExRUQ1QzY0NDgxNTA5NEM5NzRBRTg2RDk5OTFBOEVBMjAzNTJDRkNBOTQ5MDA5MTQ2RkREMzcyQTg5RTk0NEJDMTlBQzkyNkI5RjQxOUREM0NEQUFGMjYwRTcwMjkwQzA2RTM0OEZDNTRGRjMxNDNBNTk5ODUyNTg3MEJBMEI2NTY4MTFENTY1NDMxQTM3RDdCNTJBOTk2ODgyQUEwNDY3RjMzNzdCRDg0NTE4OUFFOUZGQjA0RUNFNjNGNzU3OEZBOTZGNEMzMTNBNkQ4NjEwMjAzMDEwMDAxQTMzNTMwMzMzMDBDMDYwMzU1MUQxMzAxMDFGRjA0MDIzMDAwMzAwRTA2MDM1NTFEMEYwMTAxRkYwNDA0MDMwMjA1RTAzMDEzMDYwMzU1MUQyNTA0MEMzMDBBMDYwODJCMDYwMTA1MDUwNzAzMDMzMDBEMDYwOTJBODY0ODg2RjcwRDAxMDEwQjA1MDAwMzgyMDEwMTAwNkM2RDlDMkMxOTZDODc4RjkzOUFEM0M4MTdDNUYyMjlFQkYxQkFEM0Y5OEU0RDlCNEMzRjM4MzJCNjYyMjMwRjc1OEZDRkY1ODEyMDJEMEM3OEFCRDAwMUQ5QjBBREEwRUNDMzVFNkE5MTVEQzg4MzA1NEM3MDk4ODk3QTg2QzM1Mjk2M0ZBNjE1RkZBQjZFMDAwNDQyMjIyQTYwMDA2QjA2RjZGNjdFQUIyODdDODc2MjA1RjA3ODg3QTVENUFBMjAwNTc0QzA5NjZGOUY1Qzg1NjdDRjIyRUE0RkM5RkM3ODQ4RTYzQjQ5MDE4QzA0ODJFRjhCNzU3RTVDNkFEMUU5RUE3NjQzNDEyOUQzMTU0OEIzRkZCRTZEQjlBODgzQTdCRDdGOUJFRTAxMTk1OTIzNTQ4OEEwRDZDNTdCRkVBMUQ3ODk5NzJFREE1NDFDNEJBNkNDNjY5NDYxN0ZFQjdBNDQwNDI1ODVFRjY2Q0I1NDI4NTc3MjQ2RjQ5OTBCQTkwMkU0NUZBNjQ4NjZFM0JCMEMwMTVBQ0QwNThGNDg4QThGMjNBNkZENEIxQ0IxOTYxNzA3ODMzNDNFNTU4NzZBRjhENzVGRDNGMkY2RDdDOURBQTg5NjAzREZCQUVCQ0U4QjJEMTM2QzA0NDMyMjNDQkIwRERBN0U2ODgzM0IzMTgyMDVFRTMwODIwNUVBMDIwMTAxMzA3MDMwNTgzMTBCMzAwOTA2MDM1NTA0MDYxMzAyNDM0RTMxMjUzMDIzMDYwMzU1MDQwQTBDMUM0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU2OUM4OUU5OTk5MEU1ODVBQ0U1OEZCODMxMjIzMDIwMDYwMzU1MDQwMzBDMTk0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU3QURCRUU3QUJBMEU4ODA4NTAyMTQ1QjdBRjdBMDRFRDAzQkYyNTdDOTY1RUVCODYwQzIwRDY5REMwRERBMzAwRDA2MDk2MDg2NDgwMTY1MDMwNDAyMDEwNTAwQTA4MjA0NEYzMDE4MDYwOTJBODY0ODg2RjcwRDAxMDkwMzMxMEIwNjA5MkE4NjQ4ODZGNzBEMDEwNzAxMzAyRjA2MDkyQTg2NDg4NkY3MEQwMTA5MDQzMTIyMDQyMEZBNURENzRCMEEwQTZDMjRBMTU0NTRENjY3RDdFMUIzRkJGRTZGOUNGMzQzNDk0NUFBOUQ0QTU3MjY1RUY1MDIzMDgyMDQwMDA2MDkyQTgxMUM4NkVGMzIwMjAxMDIzMTgyMDNGMTMwODIwM0VEMEMxQzQzNjk3MDY4NjU3MjQyNkY3ODIwRTZCNThCRThBRjk1RTc5NEI1RTVBRDkwRTU4REIwRTdBQkEwMDIwMTAxMEMwQ0U0QkM4MUU0Qjg5QUU1ODVBQ0U3QUJBMDE4MEYzMjMwMzIzNTMwMzEzMTMwMzAzODMwMzAzMDMwNUExODBGMzIzMDMyMzUzMDMxMzEzMDMwMzgzMDMwMzAzMDVBMTgwRjMyMzAzMzM1MzAzMTMxMzAzMDM4MzAzMDMwMzA1QTA0MjA2NTU5MzIxQTc3OUI0QjhEQkY3NjM0QUNGNUU1RkQ1Qzg4QzM4NTc2QzJFQ0MxRTg0QTJBN0NGRDQwNDc1NzQzMDQ4MjAzNjUzMDgyMDM2MTMwODIwMjQ5QTAwMzAyMDEwMjAyMTQ2ODM2MDk4QjVBNjMxOTMxREQ4RjJCMzZFRDU0MzM2QjFBRjlBODRFMzAwRDA2MDkyQTg2NDg4NkY3MEQwMTAxMEIwNTAwMzA1ODMxMEIzMDA5MDYwMzU1MDQwNjEzMDI0MzRFMzEyNTMwMjMwNjAzNTUwNDBBMEMxQzQzNjk3MDY4NjU3MjQyNkY3ODIwRTZCNThCRThBRjk1RTY5Qzg5RTk5OTkwRTU4NUFDRTU4RkI4MzEyMjMwMjAwNjAzNTUwNDAzMEMxOTQzNjk3MDY4NjU3MjQyNkY3ODIwRTZCNThCRThBRjk1RTU4OEI2RTdBQkEwRTg4MDg1MzAxRTE3MEQzMjM0MzAzMTMwMzEzMDMwMzAzMDMwMzA1QTE3MEQzMzM2MzAzMTMwMzEzMDMwMzAzMDMwMzA1QTMwNTgzMTBCMzAwOTA2MDM1NTA0MDYxMzAyNDM0RTMxMjUzMDIzMDYwMzU1MDQwQTBDMUM0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU2OUM4OUU5OTk5MEU1ODVBQ0U1OEZCODMxMjIzMDIwMDYwMzU1MDQwMzBDMTk0MzY5NzA2ODY1NzI0MjZGNzgyMEU2QjU4QkU4QUY5NUU1ODhCNkU3QUJBMEU4ODA4NTMwODIwMTIyMzAwRDA2MDkyQTg2NDg4NkY3MEQwMTAxMDEwNTAwMDM4MjAxMEYwMDMwODIwMTBBMDI4MjAxMDEwMEU4RDI5OEUxNDk3MkNBQzY5Q0YyRTY3OTY4QzgwMTYwRThFMTg2MzM5MTVBQzQyMzhENUM3QzI3OTdBREY4RTAzNTFFRjYyRUVBMjdGN0NCMTM1MTE0NUQyMDYyRTQ3NDE3OTc2QzEwMDA1NEZENEEwODNCMjAzODc0RTYwMkQwRDA4RjRFQUE0NzUxMEM2QkI2RkY3MkI1ODU0NDRFODA3RUQxOTMxRjlCNTRCMEY0MkE4Q0M1QjE5N0Y4NDAxRDc1MzVCMjFFRTZDODk3Q0QyRTE0MzBFOTFCMDdGMEYxMkEzQkVDQ0NFOTk1MUJEQkQxQTMwOURFMEZFRjQ5NkU2Q0UzMEI4RTJGRUY2QTJERDk5MzYxMDk2QjlBRkJBNkJBNTg3OEVEREQ5NjNEQzBEREI5QTNENjc0NEI4MzlDMzZEMTRGNTlCQkJEQjA3OUJDMkY3QkYzMzk2NkJBMEUwMjE0QURFMTk3QjkyNjVFNDU3NjhFMkYyRjhBNjJCM0UxNTExMzY1RjRCMDExMDFGMjlCODFCRTgxQkQ0MjdCQTlDNUZENUYzNEZCMEI2REQ1MUJFRjk5OUEwQTEwNzM1NjIwRkJGRDJBMzlFRERGRjZCNkU0MTk1NjQwMDgyQjdGNTczQTRBREEyOEZFRTRBNDg5MDM1OEVFRjFDNzZEMDIwMzAxMDAwMUEzMjMzMDIxMzAwRjA2MDM1NTFEMTMwMTAxRkYwNDA1MzAwMzAxMDFGRjMwMEUwNjAzNTUxRDBGMDEwMUZGMDQwNDAzMDIwMTg2MzAwRDA2MDkyQTg2NDg4NkY3MEQwMTAxMEIwNTAwMDM4MjAxMDEwMEI5NUIxQzEyMUI5M0Q0RUQ3MUM2RUVEMjQxQzVGRjVCRDhEQTQ1MkJDRTJBMTA1OTZCMjMzOEQ1NzQ5N0NDQjk0NkU0RkYyQTExMTcyRDI0Nzc0NThENzU1Q0Q1NDREQzY0NzM1MzQ2QzdGOTY1QjI3NTE5MERFQzU2QTMzQUYxMEVEQkM1MThDRUZCNUVGNUM1MTYwOENFNjgxMzEyRjMwN0I4QTVERTNDQzQ5RkIxNjlDRjE2M0VDOTk0RTY3MDFDMjRFMjAyQTk2RUIxRTU2OTUzN0NGREFFNTc1MTg3NzgzRjhBMURGRTlFMUFBOTVERjA0MjA4RDk1NzdFODdFREZCRDk5QzM2QkNBOUM5MjQwRkRFM0Y1REM2NjNFM0JDQTIxODlEMjUwOUFGMDZDQzkwNjhGNjZCMDQ5NEY5QURDQTcwNDkwODU2MjYzRDlDNDAyMzQ3MDcyRUI4RDFBOTcyRDU1MkUxRTJFMzM2QjNCMEVERDlFQkZCMjgyMTY2OEVGODg3QjYxOURBN0UxRDZCNUY1RkMwN0NBNzhCRTNCNjREOUQ3QzFGQzZENTkwMzc2NTY3MjRFMjdDNjMwQjQwOEVFREVGQTJDOTIzQTU3ODMyMzA4REUyRUIxMDg1RDcyRjVEODg2NUVENDcxNEQyREM3ODZCNDA1MDkxMzAwRDA2MDkyQTg2NDg4NkY3MEQwMTAxMEIwNTAwMDQ4MjAxMDA0RThERjYzRkMyNDdFMEY5QTAxNDdCQjczMzVFQThDNzAxMTYyQURBMzdBMTg5NTc3NThCRjQ0Njc2NzI2MTVBQkJFRjZDMzA0MTYzRjhEMUJEM0Q1OTdDMTYyN0Q1QkMxOEFEQzhCNEE2N0Q1NzAzQzMzNzYwNEIwRkU1RTU2RkE4NEVFRjFCMTE0OTlBMTI1RjM2NjZDMkM4RTBBN0JBODFGRkRFNjlDMDA4OUZFQjU1MzQyNTI3RDMyQThGMzA3NTI4NjE5OEZCQzJDNjE2OEU5QzdFNzc2RTZDOTE0ODY1NzM4MTgyQUUyRDgzQjM5MDc0RDdBNDQ5QkUzNjE1RkRGRjdFMUE2OERBOTM0RDM1MUM0RTM5Mjk4MDg5Njg3QjZDNzYyNzZDMkJCNDUwQTE1REM3RTEwODI0MkZCNEYwRkMxNzU1N0RBODY5MUE3MERFNTYwMzY0NjRCN0ZBQ0E1MjlEQjk4OTQzQTk1REY2NDY4RjNGRTExMzdDQTUwMDk2MzgzRDFERTVGNDVBMjc0QURBRTI2OEVFQTEwNkYzODUwOTZGMDQ4NDlDQTU5NDYzMkI3QzU3NUJCM0Y0NjVCQzVEMEVBNTA3MTVGOTgwQjBDNkY4RTc5ODI5MTM5MDgyQkE2M0QwNTgzRjY4QTVBMTAwNTczRjlFMkE1QjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwPgovQnl0ZVJhbmdlIFswIDkyMCAxMDk5MCA1MDVdICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCi9UeXBlIC9TaWcKL0ZpbHRlciAvQWRvYmUuUFBLTGl0ZQovU3ViRmlsdGVyIC9hZGJlLnBrY3M3LmRldGFjaGVkCi9NIChEXDA3MjIwMjYxMTAxMTIwNDI2XDA1MzA4XDA0NzAwXDA0NykKPj4KZW5kb2JqCnhyZWYKMCAyCjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDQzMSAwMDAwMCBuIAozIDIKMDAwMDAwMDU0MiAwMDAwMCBuIAowMDAwMDAwNjIxIDAwMDAwIG4gCjYgMwowMDAwMDAwNzI5IDAwMDAwIG4gCjAwMDAwMDA3ODAgMDAwMDAgbiAKMDAwMDAwMDg5OSAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDkKL1Jvb3QgMyAwIFIKL0luZm8gMSAwIFIKL0lEIFsgPGYyZTRmZWFhZWRkMjZiZWUzMGNiN2VjMjAyMDZjMThkPiA8Yjg0NmMxZDc3Y2QwMzBkMzQ0N2Q3ODFlOWY2NjQwZTE+IF0KL1ByZXYgMjU2Cj4+CnN0YXJ0eHJlZgoxMTE4MgolJUVPRgo=';
  const SAMPLE_TS_B64 = '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';
  const SAMPLE_GB_TS_B64 = 'MIIEHAYJKoZIhvcNAQcCoIIEDTCCBAkCAQMxDDAKBggqgRzPVQGDETCB1AYLKoZIhvcNAQkQAQSggcQEgcEwgb4CAQEGCiqBHM9VBgEEAQEwLjAKBggqgRzPVQGDEQQgWJk8w1vPivF0b2at0xyKZ6CjP2og9FVC8zdSqG1SE/gCBgHXupexohgPMjAyNjA2MDEwOTMwMDBaMAYCAQCAAQoBAf8CBBEiM0SgU6RRME8xLjAsBgNVBAoMJUNpcGhlckJveCDmtYvor5Xml7bpl7TmiLPmnI3liqHkuK3lv4MxHTAbBgNVBAMMFENpcGhlckJveCDlm73lr4YgVFNBoIIBoTCCAZ0wggFDoAMCAQICExviuLxS+6Dq6HzJC5g1Uy0Y1u4wCgYIKoEcz1UBg3UwTzEuMCwGA1UECgwlQ2lwaGVyQm94IOa1i+ivleaXtumXtOaIs+acjeWKoeS4reW/gzEdMBsGA1UEAwwUQ2lwaGVyQm94IOWbveWvhiBUU0EwHhcNMjQwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjBPMS4wLAYDVQQKDCVDaXBoZXJCb3gg5rWL6K+V5pe26Ze05oiz5pyN5Yqh5Lit5b+DMR0wGwYDVQQDDBRDaXBoZXJCb3gg5Zu95a+GIFRTQTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABLUUlubh/iui7HW3QOtn2M09FjGP/RuS+FgHN+eHdkphVzO2swjfKTp371lQhzxwwalRCPNI2BvIIlRbfPAZPv4wCgYIKoEcz1UBg3UDSAAwRQIhAPXYOCf/4DYD0a0BA0TV9xdPAK4jS+SUbIZocp5SD58lAiBp786XrX+57DgxtJXQJV3qi7z2L1io+FUQczfwRcy2yjGCAXgwggF0AgEBMGYwTzEuMCwGA1UECgwlQ2lwaGVyQm94IOa1i+ivleaXtumXtOaIs+acjeWKoeS4reW/gzEdMBsGA1UEAwwUQ2lwaGVyQm94IOWbveWvhiBUU0ECExviuLxS+6Dq6HzJC5g1Uy0Y1u4wCgYIKoEcz1UBgxGggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjA2MDEwOTMwMDBaMC8GCSqGSIb3DQEJBDEiBCBYmTzDW8+K8XRvZq3THIpnoKM/aiD0VULzN1KobVIT+DA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCA497UMi1AuYUj99D0tB0urP2v1mVyKtU4LTcvevAH63TAKBggqgRzPVQGDdQRIMEYCIQCIKxzm3XZWjQDCkstbGurNfZLMYeZHXZKCjGLrPGQ+uAIhAO8YN4RHT6f+yUQ6XZrHIlepsanlCMfoiM9YQlJdn3vr';
  const SAMPLE_TS_TEXT = 'A demo message for timestamp verification.';

  /* ---------------- 通用渲染工具 ---------------- */
  const STATUS = {
    pass: ['badge-ok', '通过'],
    warn: ['badge-warn', '需人工确认'],
    fail: ['badge-bad', '不通过']
  };

  function statusBadge(status) {
    const s = STATUS[status] || STATUS.fail;
    return el('span', { class: 'badge ' + s[0] }, [s[1]]);
  }

  function cell(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'string' || typeof v === 'number') return String(v);
    return v;
  }

  function table(headers, rows) {
    const thead = el('thead', {}, [el('tr', {}, headers.map((h) => el('th', {}, [h])))]);
    const tbody = el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, [cell(c)])))));
    return el('table', { class: 'grid' }, [thead, tbody]);
  }

  function b64ToPem(b64) {
    const clean = String(b64 || '').replace(/\s+/g, '');
    const lines = clean.match(/.{1,64}/g) || [];
    return '-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n';
  }

  function downloadText(text, filename) {
    try {
      // PEM 为纯 ASCII，直接使用 data URL，避免依赖 Blob URL
      const a = el('a', {
        href: 'data:application/x-pem-file;base64,' + btoa(text),
        download: filename
      });
      document.body.appendChild(a);
      a.click();
      a.remove();
      CB.toast('证书已导出：' + filename, 'success');
    } catch (e) {
      CB.toast('证书导出失败，请重试', 'error');
    }
  }

  function copyBtn(text) {
    return el('button', {
      type: 'button', class: 'btn btn-mini',
      onclick: () => CB.copyText(text || '')
    }, ['复制']);
  }

  function pre(text, rows) {
    return el('pre', {
      class: 'mono',
      style: 'white-space:pre-wrap;word-break:break-all;margin:6px 0;font-size:12.5px;max-height:' +
        (rows ? rows * 22 : 200) + 'px;overflow:auto;background:#f7f9fc;padding:8px;border-radius:6px'
    }, [text || '-']);
  }

  function approxBytes(b64) {
    return Math.floor(String(b64 || '').length * 3 / 4);
  }

  /* ===================================================================== */
  /* 电子签章校验                                                           */
  /* ===================================================================== */

  function renderDetails(sig) {
    const d = sig.details || {};
    const box = el('div', { class: 'mt12' });

    box.appendChild(el('div', { class: 'field-label' }, ['签章信息']));
    box.appendChild(table(['项目', '内容'], [
      ['印章名称', d.sealName || '-'],
      ['印章版本', d.sealVersion !== undefined && d.sealVersion !== '-' ? 'v' + d.sealVersion : '-'],
      ['印章类型', d.sealType && d.sealType !== '-' ? d.sealType : '无独立印章结构'],
      ['签章版本', 'v' + (d.signVersion || 1)],
      ['印章创建时间', d.sealCreateTime || '-'],
      ['印章有效期', (d.sealStartTime || '-') + ' 至 ' + (d.sealEndTime || '-')],
      ['签章时间', d.signTime || '-'],
      ['签章算法', (d.signAlgorithm || '-') + ' / ' + (d.digestAlgorithm || '-')],
      ['公钥算法', d.publicKeyAlg || '-']
    ]));

    const pubRow = el('div', { class: 'mt8' });
    pubRow.appendChild(el('div', { class: 'field-label' }, ['公钥（SubjectPublicKeyInfo Base64）']));
    pubRow.appendChild(pre(d.publicKey || '-', 3));
    pubRow.appendChild(copyBtn(d.publicKey));
    box.appendChild(pubRow);

    box.appendChild(el('div', { class: 'field-label mt12' }, ['摘要（原文摘要 / messageDigest）']));
    box.appendChild(pre(d.orgDataDigest || '-', 2));
    box.appendChild(copyBtn(d.orgDataDigest));

    box.appendChild(el('div', { class: 'field-label mt12' }, ['签名值']));
    box.appendChild(pre(d.signData || '-', 4));
    box.appendChild(copyBtn(d.signData));

    box.appendChild(el('div', { class: 'field-label mt12' }, ['原文数据（' + (d.orgDataLength || 0) + ' 字节）']));
    box.appendChild(pre(d.orgData || '-', 8));
    box.appendChild(copyBtn(d.orgData));

    if (d.signCert) {
      box.appendChild(el('div', { class: 'field-label mt12' }, ['签章者证书']));
      box.appendChild(pre(d.signCertString || '', 7));
      box.appendChild(el('button', {
        type: 'button', class: 'btn btn-mini',
        onclick: () => downloadText(b64ToPem(d.signCert), 'signer-cert-' + (sig.index + 1) + '.pem')
      }, ['导出证书']));
    }
    if (d.makerCert) {
      box.appendChild(el('div', { class: 'field-label mt12' }, ['制章者证书']));
      box.appendChild(pre(d.makerCertString || '', 7));
      box.appendChild(el('button', {
        type: 'button', class: 'btn btn-mini',
        onclick: () => downloadText(b64ToPem(d.makerCert), 'maker-cert-' + (sig.index + 1) + '.pem')
      }, ['导出证书']));
    }
    const chain = (d.chain && d.chain.certs) || [];
    chain.forEach((cert, i) => {
      const wrap = el('div', { class: 'mt12' });
      wrap.appendChild(el('div', { class: 'field-label' }, [
        '签章人证书链 ' + (i + 1) + (i === 0 ? '（签章者）' : '')
      ]));
      wrap.appendChild(pre(cert.text || '', 7));
      if (cert.base64) {
        wrap.appendChild(el('button', {
          type: 'button', class: 'btn btn-mini',
          onclick: () => downloadText(b64ToPem(cert.base64), 'chain-' + (sig.index + 1) + '-' + (i + 1) + '.pem')
        }, ['导出证书']));
      }
      box.appendChild(wrap);
    });

    if (d.references && d.references.length) {
      box.appendChild(el('div', { class: 'field-label mt12' }, ['引用文件摘要']));
      box.appendChild(table(['文件', '算法', '结果', '说明'], d.references.map((r) => [
        el('span', { class: 'mono' }, [r.file]),
        r.algorithm || '-',
        statusBadge(r.ok ? 'pass' : 'fail'),
        r.message || ''
      ])));
    }
    return box;
  }

  function renderSigPanels(container, ctx, data) {
    container.innerHTML = '';
    const sigs = data.signatures || [];
    if (!sigs.length) {
      container.appendChild(el('div', { class: 'muted' }, ['未解析到签章数据']));
      return;
    }
    let active = 0;
    const tabs = el('div', { class: 'tabs' });
    const body = el('div');

    function paint() {
      tabs.innerHTML = '';
      sigs.forEach((s, i) => {
        const btn = el('button', {
          type: 'button',
          class: 'tab' + (i === active ? ' active' : ''),
          onclick: () => { active = i; paint(); }
        }, ['签章 ' + (i + 1)]);
        tabs.appendChild(btn);
      });
      body.innerHTML = '';
      const sig = sigs[active];
      body.appendChild(el('div', { class: 'muted mt8' }, [
        (sig.format || data.fileType || '') + ' · 字段 ' + (sig.fieldName || '-') +
        (sig.subFilter ? ' · SubFilter ' + sig.subFilter : '') +
        ' · ' + (sig.allPassed ? '全部校验通过'
          : (sig.allValid ? (sig.warnCount || 0) + ' 项需人工确认' : '存在未通过项'))
      ]));
      body.appendChild(table(
        ['校验项', '状态', '说明'],
        (sig.checks || []).map((c) => [c.name, statusBadge(c.status || (c.ok ? 'pass' : 'fail')), c.message || ''])
      ));
      if (sig.warnings && sig.warnings.length) {
        body.appendChild(el('div', { class: 'mt8' }, [
          el('span', { class: 'badge badge-warn' }, ['提示']),
          el('span', { class: 'muted' }, [' ' + sig.warnings.join('；')])
        ]));
      }
      const details = el('details', { class: 'mt12' });
      details.appendChild(el('summary', { style: 'cursor:pointer;color:#0b5ed7;font-weight:600' }, ['查看签章详情']));
      details.appendChild(renderDetails(sig));
      body.appendChild(details);
    }
    paint();
    container.appendChild(tabs);
    container.appendChild(body);
  }

  function renderSigResult(box, ctx) {
    box.innerHTML = '';
    const holder = el('div');
    const summary = el('div', { 'data-result': 'sigResult', class: 'muted' }, ['尚未解析']);
    box.appendChild(summary);
    box.appendChild(holder);

    function paint() {
      const data = ctx.results.sigResult;
      if (!data || !data.signatures) {
        summary.textContent = '尚未解析，请上传签章文件后点击“解析”。';
        holder.innerHTML = '';
        return;
      }
      const sigs = data.signatures;
      const passed = sigs.filter((s) => s.allPassed).length;
      const warned = sigs.filter((s) => s.allValid && !s.allPassed).length;
      const failed = sigs.filter((s) => !s.allValid).length;
      summary.textContent = (data.fileType || '') + ' 文件，共 ' + sigs.length + ' 个签章：' +
        passed + ' 个校验全部通过' +
        (warned ? '，' + warned + ' 个存在需人工确认项' : '') +
        (failed ? '，' + failed + ' 个未通过' : '');
      summary.style.color = failed ? 'var(--danger)' : (warned ? 'var(--warn)' : 'var(--success)');
      renderSigPanels(holder, ctx, data);
    }
    ctx.__sigRender = paint;
    paint();
  }

  CB.register({
    key: 'signatrue',
    cat: 'cert',
    title: '电子签章校验',
    desc: '对 PDF / OFD 电子签章做格式、签名值、证书与印章匹配、有效期与原文摘要校验',
    help: [
      { title: '文件要求', items: ['支持 PDF 与 OFD 签章文件，单个文件不超过 10 MB。', '上传后点击“解析”才会进入校验流程。'] },
      { title: '结果说明', items: ['按签章维度展示格式、签名值、证书匹配、印章有效期、签章时间与原文摘要的校验结论。', '“需人工确认”表示该文件未提供可判定的信息（例如没有独立电子印章结构），工具不会臆断通过。'] },
      { title: '标准兼容', items: ['PDF 按 ISO 32000-2 / RFC 5652（CMS SignedData）校验 /ByteRange 与 signedAttrs。', 'OFD 按 GB/T 33190-2016 解析 Signatures.xml、SignedInfo、SignedValue（支持内联与 BaseLoc 两种布局）。', '支持 RSA / ECDSA / SM2 签名与 SHA / SM3 摘要。'] }
    ],
    state: { sigFile: '', sigData: '', sigDataFormat: 'BASE64' },
    fields: [
      {
        name: 'sigFile', label: '签章文件', type: 'file',
        accept: '.ofd,.pdf,.OFD,.PDF', span: 2,
        placeholder: '点击上传 OFD / PDF 文件，单个文件不超过 10 MB'
      },
      {
        name: 'sigData', label: '或粘贴签章文件内容', type: 'textarea',
        formatField: 'sigDataFormat', formats: [['BASE64', 'Base64'], ['HEX', '十六进制']],
        rows: 3, span: 2, placeholder: 'Base64 / 十六进制编码的 PDF 或 OFD 文件内容（上传优先）'
      }
    ],
    actions: [
      {
        name: 'parse', label: '解析', primary: true,
        run: async (ctx) => {
          const uploaded = ctx.file('sigFile');
          let raw = '';
          let fmt = 'BASE64';
          let fileName = '';
          if (uploaded && uploaded.b64) {
            raw = uploaded.b64;
            fileName = uploaded.name || '';
          } else {
            raw = String(ctx.val('sigData') || '');
            fmt = ctx.val('sigDataFormat') || 'BASE64';
          }
          if (!raw.trim()) throw new Error('请先上传签章文件或粘贴文件内容');
          if (fmt === 'BASE64' && approxBytes(raw) > 10 * 1024 * 1024) throw new Error('文件大小不能超过 10 MB');
          const data = await CB.api('/api/sig/signature/parse', {
            file: raw.replace(/\s+/g, ''), fileFormat: fmt, fileName: fileName
          });
          ctx.setResult('sigResult', data);
          const passed = data.signatures.filter((s) => s.allPassed).length;
          if (passed === data.signatures.length) {
            CB.toast('签章校验通过', 'success');
          } else if (data.signatures.every((s) => s.allValid)) {
            CB.toast('签章校验完成，存在需人工确认项', 'warn');
          } else {
            CB.toast('签章校验完成，存在未通过项', 'error');
          }
        }
      }
    ],
    results: [
      { name: 'sigResult', type: 'custom', render: renderSigResult }
    ],
    cleanup: false,
    onMount: (ctx) => {
      ctx.onResult = (name) => {
        if (name === 'sigResult' && ctx.__sigRender) ctx.__sigRender();
      };
    },
    samples: {
      parse: { sigData: SAMPLE_PDF_B64 }
    }
  });

  /* ===================================================================== */
  /* 时间戳解析与验证                                                        */
  /* ===================================================================== */

  const TS_ROWS = [
    ['版本', 'version'],
    ['序列号', 'serialNumber'],
    ['时间戳时间', 'genTimeStr'],
    ['Nonce', 'nonce'],
    ['哈希算法', 'hashAlgorithm'],
    ['签名算法', 'signatureAlgorithm'],
    ['TSA 名称', 'tsaName'],
    ['策略 OID', 'policy'],
    ['精度', 'accuracyText'],
    ['排序标志', 'ordering'],
    ['令牌类型', 'tokenType'],
    ['消息摘要', 'messageImprint']
  ];

  function renderTsResult(box, ctx) {
    box.innerHTML = '';
    const summary = el('div', { 'data-result': 'tsResult', class: 'muted' }, ['尚未解析']);
    const holder = el('div');
    box.appendChild(summary);
    box.appendChild(holder);

    function paint() {
      const data = ctx.results.tsResult;
      holder.innerHTML = '';
      if (!data) {
        summary.textContent = '尚未解析，请输入或上传时间戳令牌后点击“解析时间戳”。';
        return;
      }
      summary.textContent = '版本 ' + data.version + ' · TSA ' + (data.tsaName || '-') +
        ' · 时间 ' + (data.genTimeStr || '-') + ' · 摘要 ' + (data.hashAlgorithm || '-');

      const rows = TS_ROWS.map(([label, key]) => {
        let value = data[key];
        if (key === 'ordering') value = data.ordering ? '是' : '否';
        if (key === 'accuracyText') value = data.accuracyText || '-';
        if (value === null || value === undefined || value === '') value = '-';
        if (key === 'messageImprint') {
          return [label, el('div', { class: 'mono', style: 'word-break:break-all' }, [String(value)]), copyBtn(value)];
        }
        return [label, String(value), ''];
      });
      holder.appendChild(table(['字段', '值', ''], rows));

      const certs = data.certificateDetails || [];
      if (certs.length) {
        holder.appendChild(el('div', { class: 'field-label mt12' }, ['证书']));
        certs.forEach((c, i) => {
          const wrap = el('div', { class: 'mt8' });
          wrap.appendChild(el('div', { class: 'muted' }, ['证书 ' + (i + 1) + '：' + (c.subject || '-')]));
          wrap.appendChild(pre(c.certInfo || '', 8));
          if (c.base64) {
            wrap.appendChild(el('button', {
              type: 'button', class: 'btn btn-mini',
              onclick: () => downloadText(b64ToPem(c.base64), 'timestamp-certificate-' + (i + 1) + '.pem')
            }, ['下载证书']));
          }
          holder.appendChild(wrap);
        });
      }
    }
    ctx.__tsRender = paint;
    paint();
  }

  function renderTsVerify(box, ctx) {
    box.innerHTML = '';
    const summary = el('div', { 'data-result': 'tsVerify', class: 'muted' }, ['尚未验证']);
    const holder = el('div');
    box.appendChild(summary);
    box.appendChild(holder);

    function paint() {
      const data = ctx.results.tsVerify;
      holder.innerHTML = '';
      if (!data) {
        summary.textContent = '尚未验证，请输入令牌与原始数据后点击“验证时间戳”。';
        return;
      }
      summary.textContent = data.message || (data.valid ? '时间戳验证通过' : '时间戳验证失败');
      summary.style.color = data.valid ? 'var(--success)' : 'var(--danger)';
      holder.appendChild(el('div', { class: 'mt8' }, [
        el('span', { class: 'badge ' + (data.valid ? 'badge-ok' : 'badge-bad') }, [data.valid ? '验证通过' : '验证失败']),
        el('span', { class: 'muted' }, [' ' + (data.message || '')])
      ]));
      const rows = [
        ['CMS 签名验证', data.signatureValid ? '通过' : '未通过', data.signatureMessage || ''],
        ['原文摘要比对',
          data.digestMatch === null || data.digestMatch === undefined ? '未比对' : (data.digestMatch ? '一致' : '不一致'),
          data.expectedDigest ? ('期望 ' + data.expectedDigest + '，实际 ' + (data.computedDigest || '-')) : '未提供原始数据'],
        ['TSA 证书 / 时间有效性',
          data.timeValid === null || data.timeValid === undefined ? '未判定' : (data.timeValid ? '有效' : '无效'),
          data.timeMessage || '']
      ];
      holder.appendChild(table(['校验项', '结论', '说明'], rows.map((r) => {
        let cls = 'badge-bad';
        if (r[1] === '通过' || r[1] === '一致' || r[1] === '有效') cls = 'badge-ok';
        if (r[1] === '未比对' || r[1] === '未判定') cls = 'badge-warn';
        return [r[0], el('span', { class: 'badge ' + cls }, [r[1]]), r[2]];
      })));
    }
    ctx.__tsVerifyRender = paint;
    paint();
  }

  function buildTokenPayload(ctx) {
    let token = ctx.val('tokenData') || '';
    let fmt = ctx.val('tokenFormat') || 'BASE64';
    const uploaded = ctx.file('tokenFile');
    if (!String(token).trim() && uploaded && uploaded.b64) {
      token = uploaded.b64;
      fmt = 'BASE64';
    }
    if (!String(token).trim()) throw new Error('请输入时间戳令牌数据或上传令牌文件');
    if (fmt === 'BASE64' && approxBytes(token) > 10 * 1024 * 1024) throw new Error('令牌文件不能超过 10 MB');
    return { tokenData: String(token).replace(/\s+/g, ''), tokenFormat: fmt };
  }

  function buildOriginalPayload(ctx) {
    const uploaded = ctx.file('originalFile');
    if (uploaded && uploaded.b64) {
      return { originalData: uploaded.b64, originalFormat: 'BASE64' };
    }
    return {
      originalData: ctx.val('originalData') || '',
      originalFormat: ctx.val('originalFormat') || 'TEXT'
    };
  }

  CB.register({
    key: 'timestamp',
    cat: 'cert',
    title: '时间戳解析与验证',
    desc: '解析 RFC 3161 / GB/T 33000-2014 时间戳令牌，并用令牌内嵌证书验证签名与原文摘要',
    help: [
      { title: '令牌格式', items: ['支持 RFC 3161 TimeStampToken 与 GB/T 33000-2014 时间戳令牌。', '输入格式可选十六进制或 Base64，也可直接上传 .tsr / .tst 令牌文件。'] },
      { title: '字段说明', items: ['展示版本、序列号、时间戳时间、Nonce、哈希算法、签名算法、TSA 名称、策略 OID、精度、排序标志、消息摘要与证书。'] },
      { title: '验证说明', items: ['使用令牌内嵌的 TSA 证书验证 CMS 签名，并重新计算原始数据摘要与 messageImprint 比对。', '原始数据支持文本、十六进制、Base64 或文件上传。'] }
    ],
    state: {
      tokenData: '', tokenFormat: 'BASE64',
      originalData: '', originalFormat: 'TEXT'
    },
    fields: [
      {
        name: 'tokenData', label: '时间戳令牌数据', type: 'textarea',
        formatField: 'tokenFormat', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']],
        rows: 6, placeholder: '请输入时间戳令牌数据（HEX / Base64），或上传令牌文件'
      },
      {
        name: 'tokenFile', label: '上传令牌文件', type: 'file', accept: '.tsr,.tst,.ts,.bin,.der',
        placeholder: '选择 .tsr / .tst 令牌文件（不超过 10 MB）'
      },
      {
        name: 'originalData', label: '原始数据', type: 'textarea',
        formatField: 'originalFormat', formats: [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']],
        rows: 4, placeholder: '请输入生成时间戳时使用的原始数据'
      },
      {
        name: 'originalFile', label: '上传原始文件', type: 'file',
        placeholder: '选择原始数据文件（不超过 10 MB）'
      }
    ],
    actions: [
      {
        name: 'parse', label: '解析时间戳', primary: true,
        run: async (ctx) => {
          const payload = buildTokenPayload(ctx);
          const data = await CB.api('/api/sig/timestamp/parse', payload);
          ctx.setResult('tsResult', data);
          CB.toast('时间戳解析成功', 'success');
        }
      },
      {
        name: 'verify', label: '验证时间戳',
        run: async (ctx) => {
          const payload = buildTokenPayload(ctx);
          const original = buildOriginalPayload(ctx);
          if (!original.originalData) throw new Error('请输入或上传需要验证的原始数据');
          const data = await CB.api('/api/sig/timestamp/verify', Object.assign(payload, original));
          ctx.setResult('tsVerify', data);
          CB.toast(data.message || (data.valid ? '时间戳验证通过' : '时间戳验证失败'), data.valid ? 'success' : 'error');
        }
      }
    ],
    results: [
      { name: 'tsResult', type: 'custom', render: renderTsResult },
      { name: 'tsVerify', type: 'custom', render: renderTsVerify }
    ],
    cleanup: false,
    onMount: (ctx) => {
      ctx.onResult = (name) => {
        if (name === 'tsResult' && ctx.__tsRender) ctx.__tsRender();
        if (name === 'tsVerify' && ctx.__tsVerifyRender) ctx.__tsVerifyRender();
      };
    },
    samples: {
      parse: { tokenData: SAMPLE_TS_B64 },
      verify: { tokenData: SAMPLE_GB_TS_B64, originalData: SAMPLE_TS_TEXT }
    }
  });
})();
