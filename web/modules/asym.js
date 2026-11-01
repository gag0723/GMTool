/* 非对称算法：SM2 / RSA / ECDSA / 公钥附件（Attach&Detach） / 曲线点压缩
 * 全部请求本地后端 /api/asym/*，纯本地真算，无外链。
 */
(function () {
  'use strict';

    /* 以下为内置示例常量（仅用于「示例」，均为测试数据） */
  const SM2_D = "53B09E34311A8C499EE4867FD8F62B4B7647C114F67CD695CC572158E030242D";
  const SM2_PUB = "44A09E2BC536F7612B2CB64EF145CF3BEF6F010218A600C258AF7ACD96DD594B4EA7EFA3514909839025730218BC336AF27BF7073CE762E3A59C6E23678F3463";
  const SM2_PUB_FULL = "0444A09E2BC536F7612B2CB64EF145CF3BEF6F010218A600C258AF7ACD96DD594B4EA7EFA3514909839025730218BC336AF27BF7073CE762E3A59C6E23678F3463";
  const SM2_CIPHER = "4C93963F35F560ED3E098B88231BA3C70DF08A9C8753D2233C36BB61A14439ECD5403F42194BD035E50CF8E5B4E6AB3F3C782959C0831ACEFBF7F6459E09FB2A8D404217E0B0182B84CF7889B2067235E81D491A437474079CBB64389C395A05BBC1E4";
  const SM2_COMPRESSED = "0344A09E2BC536F7612B2CB64EF145CF3BEF6F010218A600C258AF7ACD96DD594B";
  const SM2_SIG = "9FA6292D59A16BA377CA8F08298430C0EC3C06A50700A56307A9FF101A0445598B7F16A0B153E7FAA29345FA853354691F75DA6C27F71ECF7BC661333FBCD784";
  const SM2_SIG1 = "F1BE36BDFBB9121E12AC738EB05C2D6FE1D4F35C09C357DED5EFDA998AF20493AAC8CD4CAB7994E591FE21608CE970D5300BE7DE313AA654F10D2CA9F08253D2";
  const SM2_SIG2 = "6C74E35EF28171C8E5450D4E0A5730DE2CDFDD25BFE2ABE582EB9348CC67205F780AF0DF64A7FD83A6DEFF99B090BA4BF5FE695C6DEFD31F6213D37145E40E28";
  const SM2_ATTACH = "0444A09E2BC536F7612B2CB64EF145CF3BEF6F010218A600C258AF7ACD96DD594B4EA7EFA3514909839025730218BC336AF27BF7073CE762E3A59C6E23678F346331323334353637383132333435363738";
  const SM2_ATTACH_PKG = "0444A09E2BC536F7612B2CB64EF145CF3BEF6F010218A600C258AF7ACD96DD594B4EA7EFA3514909839025730218BC336AF27BF7073CE762E3A59C6E23678F34633132333435363738313233343536373821343390A6BEF8BDC687CE38FA342A35C7805384A9E7714B31CA5599BA599732E309C867DA3113CC8F732B99238BC7E1D1F994D43660023E0E5849D20340903D";
  const SM2_PRIV_PEM = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgU7CeNDEajEme5IZ/\n2PYrS3ZHwRT2fNaVzFchWOAwJC2gCgYIKoEcz1UBgi2hRANCAAREoJ4rxTb3YSss\ntk7xRc87728BAhimAMJYr3rNlt1ZS06n76NRSQmDkCVzAhi8M2rye/cHPOdi46Wc\nbiNnjzRj\n-----END PRIVATE KEY-----";
  const SM2_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIBfDCCASGgAwIBAgIUTLN3kNpqMN4mZ8ZK51hMET8YhH0wCgYIKoEcz1UBg3Uw\nEzERMA8GA1UEAwwIU00yIFRlc3QwHhcNMjYxMTAxMDM1MjI0WhcNMjYxMjAxMDM1\nMjI0WjATMREwDwYDVQQDDAhTTTIgVGVzdDBZMBMGByqGSM49AgEGCCqBHM9VAYIt\nA0IABMgfDRogXuEeI99C67UbR2QheDMHkjKEE/pi8fxavEa8zlUWaE0gErdfJNFM\nQgxdDU+1LX8044xvu5CmBjnm4iujUzBRMB0GA1UdDgQWBBR6tIMScVVrl6vOeSSG\niLu1AjoPVzAfBgNVHSMEGDAWgBR6tIMScVVrl6vOeSSGiLu1AjoPVzAPBgNVHRMB\nAf8EBTADAQH/MAoGCCqBHM9VAYN1A0kAMEYCIQDK/iUL605pH8l0Gb/n/P575Lfc\nrKslNmSzHiyeLSJc1AIhAPn+VxWbUey0Qd4jtEN4R2UFKB7La8Lw8ncyzpjW6GHJ\n-----END CERTIFICATE-----";
  const RSA_PRIV = "308204BC020100300D06092A864886F70D0101010500048204A6308204A20201000282010100A8B7F376C9C2BFFFA212A18106745E00140F4B1714B975CD10BB3D85BF89CA79066093F9269E53878B4BD33882A40A0859C1F114B47C04820D7421172CE395FF12134F0FDF6BCB18075212B2E79D2969132D5414EF78CB4A45B8BCCBBED7242E55E3902422E8507ECE1D764D07D891C0C6CA8AEC7AFDD6862F8D9C52E20D7BB7E89454C076711B0FFEAD246EE2BCAF9D73F57D383D95C9B107E3C82DD4C8AE8E9527319BDFCA542F7776CA67F6BE99794E7BF7B3C7BC43B9BCBCD259EC8671454FCF6F0C2FF4B923771CA7313EA2FA8A1582802A3E43FBB43C5180443C26A3A97D27F514032E6BE0EE07AD8D0489CA7B0638B6EEECDD5A3E812478699B743AF7020301000102820100116FD57B28E0A0EC355EB1E4A8FB477DC03FA6608FCA97B8A65530F20CE370E804CC8AC3D205C4973A6D0F3ADA1199B1D6E8F02C00CD326ABDCE35DF49CB3444DA24370F151049BB45826A1EA59E5204788568EE5DA381206A1D421C8285849E94A4D7504CC54565C83D364296CAD4A174F4C3852B89916D6926670A0FDA6F37331E9251DBD2F577A7E8D547380AB916238194A3F351B06B37D4409AD39AF033F89EE08E61CE4690EA115E68E1E086538126D8E0F3EC7285DCA683ED86C1F94C00A171017CB0695630348ECFA414561E19F8AD4ED9229C26BFE07E818C5425B78FC9B0CA158E0329985DEA612A44263A9D7BC1E93A01554B7134CA9B23B35E3D02818100CF7F9361EF61BAA9A07ACC34EC6BFA6545FA350D00EBE13AB4FC203D217851B6D12506A1B7DB36B267910D3699556D44CAB448B63EE2C0BB5458D1DFF944DA68E37956A79BDAE37C96B967C762993A9A97E67AA85817DB8C93AB19A500A1F7A0227ACF96987166B7667BDAA84B2D4CE390BB335148C8D01755F41ABFB600543302818100D027D8404DD7EFFA1E33A910718BB2555126218703947183C6B6AE5189FAE4CFD290D44B5C2CCF4B28E52C45CEDF4C0A814F5A151BA42BB116CE4CFCA616C53B48246B6BD73306579A8B28EE0B1526844A7C61BF83EF7073B424B85FA3EC41D0A40C53B44BEFE5F37AD3CDBCCE46A1C8BB1A65C6BA842DA62383864DB186DA2D0281802ABFBFDF876FFD03017B0B23442A22D6468A7BEF87E710EA056B8440D3EA73FB542F6AA45ABAA114345E1FF8C5B261E6B054603E9BCA1FA6F883AC0996D366A40169783EE3CF3EDAE63AA074E58D68137D8410752A610FEC7067E9CAA2CCBBB59424F52BB3907977037834DE434EBBEE8E5CE2FFB61D193215954B05803BA51D0281802D0330C457110717F348009B49B287D1E34677A196A8971383F9252104D17881686B613D1AA5A5FDFECDF010F877591E3C70486EA017944B2B3F596E990BFB82A24B1DDFA81DA4957519FAB3DF39A7A69BE4E1CE645D76D7CE70D25DFC38AED2CB66CF030218D285205E84F2FB3852EBF169F7F04D8D1FC1F9940B8AE984DBD10281806667EB324F6AF1A63DE830D17F25F537C890CCAEB1C1C02040CE9C96E06A44BE8F5C33C7B51CC72EDB66966DB649181994BAA4E6346B460B0517ED78D1AE6F0A3E576E27722CAC56934310152E1A00BD2CA4406FCE5F8C862C455706F86C2233F2CEA2F28974B0AD9D26D5EC1BF79DF58DD42AE2514AE40748C832213937F4F0";
  const RSA_PUB = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100A8B7F376C9C2BFFFA212A18106745E00140F4B1714B975CD10BB3D85BF89CA79066093F9269E53878B4BD33882A40A0859C1F114B47C04820D7421172CE395FF12134F0FDF6BCB18075212B2E79D2969132D5414EF78CB4A45B8BCCBBED7242E55E3902422E8507ECE1D764D07D891C0C6CA8AEC7AFDD6862F8D9C52E20D7BB7E89454C076711B0FFEAD246EE2BCAF9D73F57D383D95C9B107E3C82DD4C8AE8E9527319BDFCA542F7776CA67F6BE99794E7BF7B3C7BC43B9BCBCD259EC8671454FCF6F0C2FF4B923771CA7313EA2FA8A1582802A3E43FBB43C5180443C26A3A97D27F514032E6BE0EE07AD8D0489CA7B0638B6EEECDD5A3E812478699B743AF70203010001";
  const RSA_CIPHER = "0042060A8522F98E354CCCA7F45DB890067704F715149B1B3FCFBC8A43D797C37BB7592719B1D210650F1E84098A7B115417136380098E2137082FED2A0E58B4C6530EECC9A5A3F68A817F7B77B0512293C40C3B2F55FBD7895C428B848B352E191F0BBAC3E33DF12754A3E9818D572969803B82CF726333AC9D74C69386C3DEE24E124AF305F777EEDEBD980A4A27D8A80CF4018A9449A9418AEAAF32D1FD19B0FC0E03F38E7DE779A7EAB2A7209366B9D71BBEF6F75720873D5B4C4A6173D1B04747BA8A50DE600DE1A9ADDD4F9F91DD4F8AE377AA99DA4E733FB0AF015CE67FB2D5B586B9F2D0C4A3F54572BE960F21EABCC1B607BC04494ADE04160C4D28";
  const RSA_SIG = "6160A3BDF84F2D96EE08A29B2B3449AD3A1D88C84A869B0FBC1C51B4AB72CC91B2A92A7F369EE896AF8E418E24E949CE55E0D3777D2AC20CBEE7C5370DA12C0FD15B2C58D6BF70268AB378F14701890CB2AA2F2D777A51C1FE10B403CCFECF6B72BA960DFEBE821EC968A71E5A5955933003421B5CED4D0197504D7E068A8C3A9D6C90EE75D1603E8511033468FDE99BC442DFA5ACEC15598887759A361CF353ED0DAB734698C4186237A2036930578043FDE1D64FFC4294A5CAB70B93D7F1983B4AC9D29C8D839797DBA16F7151CAD3AED1C14AEF38305C82CDB5A4C010B00FE2556DFE51F99E1040C7D22CC8A556B8C45F21F7F21BD7A5D9881C298CCCB552";
  const RSA_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIICsjCCAZqgAwIBAgIEATUo7TANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBj\naXBoZXJib3ggc2FtcGxlMB4XDTI2MDEwMTAwMDAwMFoXDTM1MTIzMDAwMDAwMFow\nGzEZMBcGA1UEAwwQY2lwaGVyYm94IHNhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAKi383bJwr//ohKhgQZ0XgAUD0sXFLl1zRC7PYW/icp5BmCT\n+SaeU4eLS9M4gqQKCFnB8RS0fASCDXQhFyzjlf8SE08P32vLGAdSErLnnSlpEy1U\nFO94y0pFuLzLvtckLlXjkCQi6FB+zh12TQfYkcDGyorsev3Whi+NnFLiDXu36JRU\nwHZxGw/+rSRu4ryvnXP1fTg9lcmxB+PILdTIro6VJzGb38pUL3d2ymf2vpl5Tnv3\ns8e8Q7m8vNJZ7IZxRU/Pbwwv9LkjdxynMT6i+ooVgoAqPkP7tDxRgEQ8JqOpfSf1\nFAMua+DuB62NBInKewY4tu7s3Vo+gSR4aZt0OvcCAwEAATANBgkqhkiG9w0BAQsF\nAAOCAQEAENtLClYAwvYgjkmPymK2dhkiD9tsLU547fnyDt69JCLqugH8sVq3m+4i\n4pH5oapkWqE+IZusgz3h7rpP84pKr6bYa6DoQSkeIlnbPlubLg/ohyp0og3f2/yy\npv4RXXxfiYoVV9GEpHzW2IST8BzAeJOnrHgYArWRFV4Z04UwnnUPyR61tdnvyasi\nnPH9MxSNNx29QalPPqnNZJh/1Zy2r9HS+vDOoRG5UjF/DBzgdJCt8/Yy51GS6bPF\ng0SlssJer8Tp6diSLJHIHRff/jlWulZfWAK2Iwl1CiPSvr9KfFp9lgjby4Xsekki\nJ3bhmuQkUP6529cdp+s3kikh6To3CQ==\n-----END CERTIFICATE-----";
  const EC_D = "0F27DE12867715B449793E8F84DD98558774692A36DA691FF48321388757ECC0";
  const EC_PUB = "1E001525D71C7AD248B73AE5982F6EF38A237AE74C659894125333C06933B97B2B935F1B803CAE46DB99F5CCC5E4344D6507436E4D6E1E4EA4BEF400BBDF93D5";
  const EC_SIG = "3046022100AB994D1A4A5E6D0EF0803F1F2964A1CF5781C1CB6B52053B9F702552F1CFF4FE0221008F831CB547A4A0CD031A4FC164180DBE81749D2C7BD1F5010D3500DEC919789C";

  const KEY_FORMATS = [['HEX', '十六进制'], ['BASE64', 'Base64'], ['PEM', 'PEM 文本']];
  const BIN_FORMATS = [['HEX', '十六进制'], ['BASE64', 'Base64']];
  const DATA_FORMATS = [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const UID_FORMATS = [['HEX', '十六进制'], ['TEXT', '字符串']];
  const UID = '31323334353637383132333435363738';

  const HELP_COMMON = [
    { title: '输入格式', items: [
      '文本输入按 UTF-8 处理；十六进制输入必须为合法 HEX 字符串；Base64 输入必须为合法 Base64 编码。',
      'SM2 公钥支持 04||X||Y（65 字节）、X||Y（64 字节）与 02/03 压缩点（33 字节）。',
      '公私钥都可以选择 PEM 文本形式，后端会自动识别 -----BEGIN----- 头。'
    ] },
    { title: '计算说明', items: [
      '所有运算均在后端本地完成（GB/T 32918 SM2、RFC 8017 RSA、SEC1 ECDSA），不访问任何外部服务。',
      '十六进制结果统一大写输出。'
    ] }
  ];

  /* ------------------------------------------------------------------ SM2 */
  CB.register({
    key: 'sm2',
    cat: 'asym',
    title: 'SM2 算法',
    desc: 'SM2 密钥对、公钥校验、加解密（C1C3C2 / C1C2C3）、Z/e 值、签名验签与同 k 攻击',
    help: HELP_COMMON.concat([
      { title: 'SM2 签名', items: [
        '「基于消息」签名时，e = SM3(Z || M)，Z 由用户标识（默认 1234567812345678）与曲线参数计算。',
        '「基于 e 值」签名时直接对 32 字节 e 值签名，验签同样使用该 e 值。',
        '验签的签名值可以是 64 字节 R||S，也可以是 DER 编码（会自动识别）。'
      ] },
      { title: '验签并攻击', items: [
        '当两条签名使用了同一个随机数 k 时，可由 r、s、e 反推出私钥。',
        '若两条签名的随机数不同，反推结果与公钥不匹配，会明确报错而不会给出错误私钥。'
      ] }
    ]),
    state: {
      publicKeyFormat: 'HEX', privateKeyFormat: 'HEX', publicKey: '', privateKey: '',
      encryptMode: 'C1C3C2', message: '', messageFormat: 'TEXT',
      cipher: '', cipherFormat: 'HEX',
      userId: UID, userIdFormat: 'HEX',
      hashMode: 'noHash', hash: '', hashFormat: 'HEX',
      messageTwo: '', messageTwoFormat: 'TEXT',
      signature: '', signatureFormat: 'HEX',
      signatureTwo: '', signatureTwoFormat: 'HEX',
      signatureTarget: 'DER', cipherTarget: 'DER',
      cert: '', certFormat: 'TEXT',
      privateKeyPem: ''
    },
    formats: ['publicKeyFormat', 'privateKeyFormat', 'messageFormat', 'cipherFormat',
      'userIdFormat', 'hashFormat', 'messageTwoFormat', 'signatureFormat',
      'signatureTwoFormat', 'signatureTarget', 'cipherTarget', 'certFormat'],
    defaults: {},
    fields: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 3, formatField: 'publicKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: '公钥：04||X||Y / X||Y / 压缩点 / PEM' },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 2, formatField: 'privateKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: '32 字节私钥（HEX/BASE64）或 PKCS#8 PEM' },
      { name: 'encryptMode', label: '加密类型', type: 'radio',
        options: [['C1C3C2', 'C1||C3||C2'], ['C1C2C3', 'C1||C2||C3']] },
      { name: 'userId', label: '用户标识', type: 'input', formatField: 'userIdFormat',
        formats: UID_FORMATS, placeholder: '默认 1234567812345678（HEX: 3132...3838）' },
      { name: 'message', label: '消息', type: 'textarea', rows: 3, formatField: 'messageFormat',
        formats: DATA_FORMATS, placeholder: '待加密 / 待签名 / 待验签的消息' },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3, formatField: 'cipherFormat',
        formats: BIN_FORMATS, placeholder: 'C1||C3||C2 或 C1||C2||C3 裸密文 / DER 密文' },
      { name: 'hashMode', label: '签名模式', type: 'radio',
        options: [['noHash', '基于消息'], ['withHash', '基于 e 值']] },
      { name: 'hash', label: 'e 值（32 字节）', type: 'textarea', rows: 2, formatField: 'hashFormat',
        formats: BIN_FORMATS, placeholder: '基于 e 值签名 / 验签时填写' },
      { name: 'messageTwo', label: '消息（第二组）', type: 'textarea', rows: 2,
        formatField: 'messageTwoFormat', formats: DATA_FORMATS, placeholder: '攻击演示的第二组消息' },
      { name: 'signature', label: '签名值（第一组）', type: 'textarea', rows: 2,
        formatField: 'signatureFormat', formats: BIN_FORMATS, placeholder: 'R||S 或 DER' },
      { name: 'signatureTwo', label: '签名值（第二组）', type: 'textarea', rows: 2,
        formatField: 'signatureTwoFormat', formats: BIN_FORMATS, placeholder: 'R||S 或 DER' },
      { name: 'signatureTarget', label: '签名转换目标', type: 'select',
        options: [['DER', '转 DER 编码'], ['RAW', '转 R||S 格式']] },
      { name: 'cipherTarget', label: '密文转换目标', type: 'select',
        options: [['DER', '转 DER 编码'], ['RAW', '转裸密文']] },
      { name: 'cert', label: '证书（提取公钥）', type: 'textarea', rows: 3, formatField: 'certFormat',
        formats: [['TEXT', 'PEM 文本'], ['HEX', '十六进制'], ['BASE64', 'Base64']],
        placeholder: '粘贴 X.509 证书 PEM / DER' },
      { name: 'privateKeyPem', label: '私钥 PEM（解析）', type: 'textarea', rows: 4,
        placeholder: '-----BEGIN PRIVATE KEY----- ...' }
    ],
    actions: [
      { name: 'keypair', label: '生成密钥对', primary: true, run: async (ctx) => {
        const d = await ctx.api('/api/asym/sm2/keypair', {
          publicKeyFormat: ctx.val('publicKeyFormat'), privateKeyFormat: ctx.val('privateKeyFormat')
        });
        ctx.set('publicKey', d.publicKey); ctx.set('privateKey', d.privateKey);
        ctx.setResult('publicKey', d.publicKey);
        ctx.setResult('privateKey', d.privateKey);
        ctx.setResult('pem', d.privateKeyPem);
        ctx.refresh(); CB.toast('密钥对生成成功', 'success');
      } },
      { name: 'pubkeyCalc', label: '计算公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/pubkey/calculate', {
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          publicKeyFormat: ctx.val('publicKeyFormat')
        });
        ctx.set('publicKey', v); ctx.setResult('publicKey', v); ctx.refresh();
        CB.toast('公钥计算成功', 'success');
      } },
      { name: 'pubkeyVerify', label: '验证公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/publickey/verify', {
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat')
        });
        ctx.setResult('verifyResult', '公钥在曲线上' + (v.x ? '\nX = ' + v.x + '\nY = ' + v.y : ''));
        CB.toast('公钥在曲线上', 'success');
      } },
      { name: 'encrypt', label: '加密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/encrypt', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          encryptMode: ctx.val('encryptMode'), cipherFormat: ctx.val('cipherFormat')
        });
        ctx.set('cipher', v); ctx.setResult('cipher', v); ctx.refresh();
        CB.toast('加密成功', 'success');
      } },
      { name: 'decrypt', label: '解密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/decrypt', {
          cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          encryptMode: ctx.val('encryptMode'), messageFormat: ctx.val('messageFormat')
        });
        ctx.set('message', v); ctx.setResult('message', v); ctx.refresh();
        CB.toast('解密成功', 'success');
      } },
      { name: 'evalue', label: '计算 e 值', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/calculate/evalue', {
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat'),
          resultFormat: 'HEX', zzFormat: 'HEX'
        });
        ctx.setResult('zHash', v.zHash); ctx.setResult('eHash', v.eHash);
        ctx.setResult('info', JSON.stringify({ userId: v.userId, ENTL: v.entl }, null, 2));
        CB.toast('e 值计算成功', 'success');
      } },
      { name: 'sign', label: '签名', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/sign', {
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          hashMode: ctx.val('hashMode'),
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          hash: ctx.val('hash'), hashFormat: ctx.val('hashFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat'),
          signatureFormat: ctx.val('signatureFormat')
        });
        ctx.set('signature', v.signature); ctx.setResult('signature', v.signature);
        ctx.setResult('signatureDer', v.signatureDER); ctx.setResult('eHash', v.e); ctx.refresh();
        CB.toast('签名成功', 'success');
      } },
      { name: 'verify', label: '验签', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/verify', {
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'), publicType: 'PUB',
          hashMode: ctx.val('hashMode'),
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          hash: ctx.val('hash'), hashFormat: ctx.val('hashFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat'),
          signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat')
        });
        ctx.setResult('verifyResult', '验签通过\ne = ' + v.e);
        CB.toast('验签通过', 'success');
      } },
      { name: 'attack', label: '验签并攻击', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/verifyAndAttack', {
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'), publicType: 'PUB',
          hashMode: ctx.val('hashMode'),
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          messageTwo: ctx.val('messageTwo'), messageTwoFormat: ctx.val('messageTwoFormat'),
          hash: ctx.val('hash'), hashFormat: ctx.val('hashFormat'),
          hashTwo: ctx.val('hash'), hashTwoFormat: ctx.val('hashFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat'),
          signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat'),
          signatureTwo: ctx.val('signatureTwo'), signatureTwoFormat: ctx.val('signatureTwoFormat'),
          privateKeyFormat: 'HEX'
        });
        ctx.setResult('privateKey', v.privateKey);
        ctx.setResult('verifyResult', '攻击成功：反推出私钥\nk = ' + v.k);
        CB.toast('攻击成功：已反推私钥', 'success');
      } },
      { name: 'signatureConvert', label: '签名格式转换', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/signature/convert', {
          signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat'),
          targetFormat: ctx.val('signatureTarget')
        });
        ctx.setResult('signature', v); CB.toast('转换成功', 'success');
      } },
      { name: 'cipherConvert', label: '密文格式转换', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/cipher/convert', {
          cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
          targetFormat: ctx.val('cipherTarget'), encryptMode: ctx.val('encryptMode')
        });
        ctx.setResult('cipher', v); CB.toast('转换成功', 'success');
      } },
      { name: 'certExtract', label: '从证书提取公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/cert/extract-pubkey', {
          cert: ctx.val('cert'), certFormat: ctx.val('certFormat'),
          publicKeyFormat: ctx.val('publicKeyFormat')
        });
        ctx.set('publicKey', v); ctx.setResult('publicKey', v); ctx.refresh();
        CB.toast('已从证书中提取公钥', 'success');
      } },
      { name: 'pemParse', label: '解析私钥 PEM', run: async (ctx) => {
        const v = await ctx.api('/api/asym/sm2/private/pem/parse', {
          privateKeyPem: ctx.val('privateKeyPem'),
          publicKeyFormat: ctx.val('publicKeyFormat'), privateKeyFormat: ctx.val('privateKeyFormat')
        });
        ctx.set('privateKey', v.privateKey); ctx.set('publicKey', v.publicKey);
        ctx.setResult('privateKey', v.privateKey); ctx.setResult('publicKey', v.publicKey);
        ctx.refresh(); CB.toast('解析成功', 'success');
      } }
    ],
    results: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 2 },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 2 },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3 },
      { name: 'message', label: '消息（解密结果）', type: 'textarea', rows: 3 },
      { name: 'signature', label: '签名值', type: 'textarea', rows: 2 },
      { name: 'signatureDer', label: 'DER 签名', type: 'textarea', rows: 2 },
      { name: 'zHash', label: 'Z 值', type: 'textarea', rows: 2 },
      { name: 'eHash', label: 'e 值', type: 'textarea', rows: 2 },
      { name: 'pem', label: '私钥 PEM', type: 'textarea', rows: 5 },
      { name: 'verifyResult', label: '校验 / 验签结果', type: 'text' },
      { name: 'info', label: '附加信息', type: 'json' }
    ],
    samples: {
      keypair: {},
      pubkeyCalc: { privateKey: SM2_D },
      pubkeyVerify: { publicKey: SM2_PUB },
      encrypt: { message: 'abc', publicKey: SM2_PUB,
        encryptMode: 'C1C3C2' },
      decrypt: { cipher: SM2_CIPHER, privateKey: SM2_D,
        encryptMode: 'C1C3C2' },
      evalue: { publicKey: SM2_PUB, message: 'abc',
        userId: UID },
      sign: { privateKey: SM2_D, publicKey: SM2_PUB,
        hashMode: 'noHash', message: 'abc', userId: UID },
      verify: { publicKey: SM2_PUB, hashMode: 'noHash', message: 'abc', userId: UID, signature: SM2_SIG },
      attack: { publicKey: SM2_PUB, hashMode: 'noHash',
        message: 'message one',
        messageTwo: 'message two',
        userId: UID,
        signature: SM2_SIG1,
        signatureTwo: SM2_SIG2 },
      signatureConvert: { signature: SM2_SIG, signatureTarget: 'DER' },
      cipherConvert: { cipher: SM2_CIPHER, cipherTarget: 'DER',
        encryptMode: 'C1C3C2' },
      certExtract: { cert: SM2_CERT_PEM },
      pemParse: { privateKeyPem: SM2_PRIV_PEM }
    }
  });

  /* ------------------------------------------------------------------ RSA */
  CB.register({
    key: 'rsa',
    cat: 'asym',
    title: 'RSA 算法',
    desc: 'RSA 密钥对（1024~4096）、公钥计算、PKCS#1 v1.5 / NoPadding / OAEP 加解密与签名验签',
    help: HELP_COMMON.concat([
      { title: '填充方式', items: [
        'PKCS#1 v1.5：最常用的标准填充，加密上限为 模长-11 字节。',
        'NoPadding：不做填充，明文需自行补齐到模长，解密输出会去掉左侧补的 0x00。',
        'OAEP：默认 MGF1-SHA1，加密上限为 模长-2*摘要长度-2。'
      ] },
      { title: '签名', items: ['签名算法为 PKCS#1 v1.5 + SHA1/SHA224/SHA256/SHA384/SHA512，选择需与验签一致。'] }
    ]),
    state: {
      publicKeyFormat: 'HEX', privateKeyFormat: 'HEX', publicKey: '', privateKey: '',
      keySize: 2048,
      message: '', messageFormat: 'TEXT', cipher: '', cipherFormat: 'HEX',
      fillMethod: 'RSA/ECB/PKCS1Padding',
      signHash: 'SHA256withRSA', signature: '', signatureFormat: 'HEX',
      cert: '', certFormat: 'TEXT'
    },
    formats: ['publicKeyFormat', 'privateKeyFormat', 'messageFormat', 'cipherFormat',
      'fillMethod', 'signHash', 'signatureFormat', 'certFormat'],
    defaults: {},
    fields: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 3, formatField: 'publicKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: 'SPKI/PKCS#1 的 DER、Base64 或 PEM' },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 4, formatField: 'privateKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: 'PKCS#8/PKCS#1 的 DER、Base64 或 PEM' },
      { name: 'keySize', label: '密钥长度', type: 'select',
        options: [[1024, '1024 位'], [2048, '2048 位'], [3072, '3072 位'], [4096, '4096 位']] },
      { name: 'fillMethod', label: '填充方式', type: 'select', options: [
        ['RSA/ECB/PKCS1Padding', 'RSA/ECB/PKCS1Padding（标准填充）'],
        ['RSA/ECB/NoPadding', 'RSA/ECB/NoPadding（无填充）'],
        ['RSA/ECB/OAEPPadding', 'RSA/ECB/OAEPPadding（默认 SHA-1）']
      ] },
      { name: 'message', label: '消息', type: 'textarea', rows: 3, formatField: 'messageFormat',
        formats: DATA_FORMATS, placeholder: '待加密 / 待签名 / 待验签的消息' },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3, formatField: 'cipherFormat',
        formats: BIN_FORMATS, placeholder: '长度等于模长的密文' },
      { name: 'signHash', label: '签名算法', type: 'select', options: [
        ['SHA1withRSA', 'SHA1withRSA'], ['SHA224withRSA', 'SHA224withRSA'],
        ['SHA256withRSA', 'SHA256withRSA'], ['SHA384withRSA', 'SHA384withRSA'],
        ['SHA512withRSA', 'SHA512withRSA']
      ] },
      { name: 'signature', label: '签名值', type: 'textarea', rows: 3,
        formatField: 'signatureFormat', formats: BIN_FORMATS, placeholder: '签名值（长度等于模长）' },
      { name: 'cert', label: '证书（提取公钥）', type: 'textarea', rows: 3,
        formatField: 'certFormat', formats: [['TEXT', 'PEM 文本'], ['HEX', '十六进制'], ['BASE64', 'Base64']],
        placeholder: '粘贴 X.509 证书 PEM / DER' }
    ],
    actions: [
      { name: 'keypair', label: '生成密钥对', primary: true, run: async (ctx) => {
        const d = await ctx.api('/api/asym/rsa/keypair', {
          keySize: Number(ctx.val('keySize')) || 2048,
          publicKeyFormat: ctx.val('publicKeyFormat'), privateKeyFormat: ctx.val('privateKeyFormat')
        });
        ctx.set('publicKey', d.publicKey); ctx.set('privateKey', d.privateKey);
        ctx.setResult('publicKey', d.publicKey);
        ctx.setResult('privateKey', d.privateKey);
        ctx.setResult('info', JSON.stringify({ bits: d.bits, e: d.e }, null, 2));
        ctx.refresh(); CB.toast('密钥对生成成功（' + d.bits + ' 位）', 'success');
      } },
      { name: 'pubkeyCalc', label: '计算公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/rsa/pubkey/calculate', {
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          publicKeyFormat: ctx.val('publicKeyFormat')
        });
        ctx.set('publicKey', v); ctx.setResult('publicKey', v); ctx.refresh();
        CB.toast('公钥计算成功', 'success');
      } },
      { name: 'encrypt', label: '加密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/rsa/encrypt', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          fillMethod: ctx.val('fillMethod'), cipherFormat: ctx.val('cipherFormat')
        });
        ctx.set('cipher', v); ctx.setResult('cipher', v); ctx.refresh();
        CB.toast('加密成功', 'success');
      } },
      { name: 'decrypt', label: '解密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/rsa/decrypt', {
          cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          fillMethod: ctx.val('fillMethod'), messageFormat: ctx.val('messageFormat')
        });
        ctx.set('message', v); ctx.setResult('message', v); ctx.refresh();
        CB.toast('解密成功', 'success');
      } },
      { name: 'sign', label: '签名', run: async (ctx) => {
        const v = await ctx.api('/api/asym/rsa/sign', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          signHash: ctx.val('signHash'), signatureFormat: ctx.val('signatureFormat')
        });
        ctx.set('signature', v); ctx.setResult('signature', v); ctx.refresh();
        CB.toast('签名成功', 'success');
      } },
      { name: 'verify', label: '验签', run: async (ctx) => {
        await ctx.api('/api/asym/rsa/verify', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          signHash: ctx.val('signHash'), signature: ctx.val('signature'),
          signatureFormat: ctx.val('signatureFormat')
        });
        ctx.setResult('verifyResult', '验签通过');
        CB.toast('验签通过', 'success');
      } },
      { name: 'certExtract', label: '从证书提取公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/rsa/extract/publicKey', {
          cert: ctx.val('cert'), certFormat: ctx.val('certFormat'),
          publicKeyFormat: ctx.val('publicKeyFormat')
        });
        ctx.set('publicKey', v); ctx.setResult('publicKey', v); ctx.refresh();
        CB.toast('已从证书中提取公钥', 'success');
      } }
    ],
    results: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 3 },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 4 },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3 },
      { name: 'message', label: '消息（解密结果）', type: 'textarea', rows: 3 },
      { name: 'signature', label: '签名值', type: 'textarea', rows: 3 },
      { name: 'verifyResult', label: '验签结果', type: 'text' },
      { name: 'info', label: '密钥信息', type: 'json' }
    ],
    samples: {
      keypair: { keySize: 2048 },
      pubkeyCalc: { privateKey: RSA_PRIV },
      encrypt: { message: 'abc', publicKey: RSA_PUB,
        fillMethod: 'RSA/ECB/PKCS1Padding' },
      decrypt: { cipher: RSA_CIPHER, privateKey: RSA_PRIV, fillMethod: 'RSA/ECB/PKCS1Padding' },
      sign: { message: 'abc', privateKey: RSA_PRIV, signHash: 'SHA256withRSA' },
      verify: { message: 'abc', publicKey: RSA_PUB,
        signHash: 'SHA256withRSA', signature: RSA_SIG },
      certExtract: { cert: RSA_CERT_PEM }
    }
  });

  /* ---------------------------------------------------------------- ECDSA */
  CB.register({
    key: 'ecdsa',
    cat: 'asym',
    title: 'ECDSA 算法',
    desc: 'ECDSA 密钥对与 DER 签名验签，曲线 P-256/P-384/P-521/secp256k1/SM2',
    help: HELP_COMMON.concat([
      { title: '签名格式', items: ['签名为 ANSI X9.62 / SEC1 的 DER 编码（SEQUENCE{ r, s }）。'] },
      { title: '加密说明', items: [
        '原站 ECDSA 的「加密/解密」在非 SM2 曲线上没有真实实现；',
        '本地仅在 SM2 曲线上按 SM2 加密（C1C3C2）实现，其余曲线会如实提示「不支持 ECIES」。'
      ] }
    ]),
    state: {
      curveType: 'secp256r1', publicKeyFormat: 'HEX', privateKeyFormat: 'HEX',
      publicKey: '', privateKey: '',
      message: '', messageFormat: 'TEXT', cipher: '', cipherFormat: 'HEX',
      signHash: 'SHA256', signature: '', signatureFormat: 'HEX'
    },
    formats: ['curveType', 'publicKeyFormat', 'privateKeyFormat', 'messageFormat',
      'cipherFormat', 'signHash', 'signatureFormat'],
    defaults: {},
    fields: [
      { name: 'curveType', label: '椭圆曲线', type: 'select', options: [
        ['secp256r1', 'secp256r1 (P-256)'], ['secp384r1', 'secp384r1 (P-384)'],
        ['secp521r1', 'secp521r1 (P-521)'], ['secp256k1', 'secp256k1'],
        ['SM2', 'SM2 (sm2p256v1)']
      ] },
      { name: 'signHash', label: '哈希算法', type: 'select', options: [
        ['SHA1', 'SHA1'], ['SHA224', 'SHA224'], ['SHA256', 'SHA256'],
        ['SHA384', 'SHA384'], ['SHA512', 'SHA512']
      ] },
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 3, formatField: 'publicKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: '04||X||Y / X||Y / PEM' },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 2, formatField: 'privateKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: '私钥数值（HEX/BASE64）或 PKCS#8 PEM' },
      { name: 'message', label: '消息', type: 'textarea', rows: 3, formatField: 'messageFormat',
        formats: DATA_FORMATS, placeholder: '待签名 / 待验签 / 待加密的消息' },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3, formatField: 'cipherFormat',
        formats: BIN_FORMATS, placeholder: '仅 SM2 曲线支持 C1C3C2 密文' },
      { name: 'signature', label: '签名值（DER）', type: 'textarea', rows: 3,
        formatField: 'signatureFormat', formats: BIN_FORMATS, placeholder: 'DER 签名' }
    ],
    actions: [
      { name: 'keypair', label: '生成密钥对', primary: true, run: async (ctx) => {
        const d = await ctx.api('/api/asym/ecdsa/keypair', {
          curveType: ctx.val('curveType'),
          publicKeyFormat: ctx.val('publicKeyFormat'), privateKeyFormat: ctx.val('privateKeyFormat')
        });
        ctx.set('publicKey', d.publicKey); ctx.set('privateKey', d.privateKey);
        ctx.setResult('publicKey', d.publicKey); ctx.setResult('privateKey', d.privateKey);
        ctx.setResult('info', JSON.stringify({ curve: d.curveType }, null, 2));
        ctx.refresh(); CB.toast('密钥对生成成功', 'success');
      } },
      { name: 'sign', label: '签名', run: async (ctx) => {
        const v = await ctx.api('/api/asym/ecdsa/sign', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          signHash: ctx.val('signHash'), signatureFormat: ctx.val('signatureFormat'),
          curveType: ctx.val('curveType')
        });
        ctx.set('signature', v); ctx.setResult('signature', v); ctx.refresh();
        CB.toast('签名成功', 'success');
      } },
      { name: 'verify', label: '验签', run: async (ctx) => {
        await ctx.api('/api/asym/ecdsa/verify', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          signHash: ctx.val('signHash'), signature: ctx.val('signature'),
          signatureFormat: ctx.val('signatureFormat'), curveType: ctx.val('curveType')
        });
        ctx.setResult('verifyResult', '验签通过');
        CB.toast('验签通过', 'success');
      } },
      { name: 'encrypt', label: '加密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/ecdsa/encrypt', {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          cipherFormat: ctx.val('cipherFormat'), curveType: ctx.val('curveType')
        });
        ctx.set('cipher', v); ctx.setResult('cipher', v); ctx.refresh();
        CB.toast('加密成功', 'success');
      } },
      { name: 'decrypt', label: '解密', run: async (ctx) => {
        const v = await ctx.api('/api/asym/ecdsa/decrypt', {
          cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          messageFormat: ctx.val('messageFormat'), curveType: ctx.val('curveType')
        });
        ctx.set('message', v); ctx.setResult('message', v); ctx.refresh();
        CB.toast('解密成功', 'success');
      } }
    ],
    results: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 2 },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 2 },
      { name: 'signature', label: 'DER 签名', type: 'textarea', rows: 3 },
      { name: 'cipher', label: '密文', type: 'textarea', rows: 3 },
      { name: 'message', label: '消息（解密结果）', type: 'textarea', rows: 3 },
      { name: 'verifyResult', label: '验签结果', type: 'text' },
      { name: 'info', label: '附加信息', type: 'json' }
    ],
    samples: {
      keypair: { curveType: 'secp256r1' },
      sign: { curveType: 'secp256r1', message: 'abc',
        privateKey: EC_D, signHash: 'SHA256' },
      verify: { curveType: 'secp256r1', message: 'abc',
        publicKey: EC_PUB, signHash: 'SHA256',
        signature: EC_SIG },
      encrypt: { curveType: 'SM2', message: 'abc',
        publicKey: SM2_PUB },
      decrypt: { curveType: 'SM2', cipher: SM2_CIPHER,
        privateKey: SM2_D }
    }
  });

  /* --------------------------------------------------------------- 附件包 */
  CB.register({
    key: 'attach',
    cat: 'asym',
    title: 'SM2 公钥附件',
    desc: '把 SM2 公钥与用户标识拼装成附件包（Attach）并可分离还原（Detach），附 SM2 签名验签',
    help: [
      { title: '附件格式', items: [
        '附件包 = 04||X||Y（65 字节公钥） || 用户标识（默认 16 字节 "1234567812345678"）。',
        '签名包 = 附件包 || R||S（64 字节签名），验签时只需提供签名包与原文。'
      ] },
      { title: '与原站差异', items: [
        '原站该页面是 PKCS#7 签名封装工具（依赖证书）；本地按「SM2 公钥 + 用户标识」附件语义实现，',
        '签名使用 SM2 + SM3（Z 值包含附件中的用户标识）。'
      ] }
    ],
    state: {
      publicKeyFormat: 'HEX', publicKey: '', privateKeyFormat: 'HEX', privateKey: '',
      userId: UID, userIdFormat: 'HEX',
      message: '', messageFormat: 'TEXT',
      attachData: '', attachFormat: 'HEX',
      signature: '', signatureFormat: 'HEX',
      package: '', packageFormat: 'HEX'
    },
    formats: ['publicKeyFormat', 'privateKeyFormat', 'userIdFormat', 'messageFormat',
      'attachFormat', 'signatureFormat', 'packageFormat'],
    defaults: {},
    fields: [
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 2, formatField: 'publicKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: 'SM2 公钥（X||Y 或 04||X||Y / PEM）' },
      { name: 'privateKey', label: '私钥', type: 'textarea', rows: 2, formatField: 'privateKeyFormat',
        formats: KEY_FORMATS, span: 2, placeholder: 'SM2 私钥（签名用）' },
      { name: 'userId', label: '用户标识', type: 'input', formatField: 'userIdFormat',
        formats: UID_FORMATS, placeholder: '默认 1234567812345678' },
      { name: 'message', label: '消息', type: 'textarea', rows: 3, formatField: 'messageFormat',
        formats: DATA_FORMATS, placeholder: '待签名 / 待验签的消息' },
      { name: 'attachData', label: '附件包', type: 'textarea', rows: 3,
        formatField: 'attachFormat', formats: BIN_FORMATS, placeholder: '04||X||Y + 用户标识' },
      { name: 'package', label: '签名包（附件 + 签名）', type: 'textarea', rows: 4,
        formatField: 'packageFormat', formats: BIN_FORMATS, placeholder: '附件包 || R||S' },
      { name: 'signature', label: '签名值', type: 'textarea', rows: 2,
        formatField: 'signatureFormat', formats: BIN_FORMATS, placeholder: 'R||S（64 字节）' }
    ],
    actions: [
      { name: 'attach', label: '生成附件', primary: true, run: async (ctx) => {
        const v = await ctx.api('/api/asym/attach/attach', {
          publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat')
        });
        ctx.set('attachData', v.attachment); ctx.setResult('attachment', v.attachment);
        ctx.setResult('userId', v.userIdText + '（' + v.userId + '）');
        ctx.setResult('info', JSON.stringify({ layout: v.layout, size: v.size }, null, 2));
        ctx.refresh(); CB.toast('附件生成成功', 'success');
      } },
      { name: 'detach', label: '分离附件', run: async (ctx) => {
        const v = await ctx.api('/api/asym/attach/detach', {
          attachData: ctx.val('attachData'), attachFormat: ctx.val('attachFormat'),
          publicKeyFormat: ctx.val('publicKeyFormat'), userIdFormat: ctx.val('userIdFormat')
        });
        ctx.set('publicKey', v.publicKey); ctx.setResult('publicKey', v.publicKey);
        ctx.setResult('userId', v.userIdText + '（' + v.userId + '）');
        ctx.refresh(); CB.toast('附件分离成功', 'success');
      } },
      { name: 'sign', label: '签名', run: async (ctx) => {
        const v = await ctx.api('/api/asym/attach/sign', {
          privateKey: ctx.val('privateKey'), privateKeyFormat: ctx.val('privateKeyFormat'),
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          userId: ctx.val('userId'), userIdFormat: ctx.val('userIdFormat'),
          signatureFormat: ctx.val('signatureFormat')
        });
        ctx.set('signature', v.signature); ctx.set('package', v.package);
        ctx.setResult('signature', v.signature);
        ctx.setResult('package', v.package);
        ctx.setResult('attachment', v.attachment);
        ctx.setResult('eHash', v.e);
        ctx.refresh(); CB.toast('签名成功', 'success');
      } },
      { name: 'verify', label: '验签', run: async (ctx) => {
        const payload = {
          message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
          signatureFormat: ctx.val('signatureFormat')
        };
        if (ctx.val('package')) {
          payload.package = ctx.val('package');
          payload.packageFormat = ctx.val('packageFormat');
        } else {
          payload.publicKey = ctx.val('publicKey');
          payload.publicKeyFormat = ctx.val('publicKeyFormat');
          payload.userId = ctx.val('userId');
          payload.userIdFormat = ctx.val('userIdFormat');
          payload.signature = ctx.val('signature');
        }
        const v = await ctx.api('/api/asym/attach/verify', payload);
        ctx.setResult('verifyResult', '验签通过（公钥 ' + v.publicKey.slice(0, 16) + '…）');
        CB.toast('验签通过', 'success');
      } }
    ],
    results: [
      { name: 'attachment', label: '附件包', type: 'textarea', rows: 3 },
      { name: 'package', label: '签名包', type: 'textarea', rows: 4 },
      { name: 'publicKey', label: '公钥', type: 'textarea', rows: 2 },
      { name: 'signature', label: '签名值', type: 'textarea', rows: 2 },
      { name: 'userId', label: '用户标识', type: 'text' },
      { name: 'eHash', label: 'e 值', type: 'textarea', rows: 2 },
      { name: 'verifyResult', label: '验签结果', type: 'text' },
      { name: 'info', label: '附件结构', type: 'json' }
    ],
    samples: {
      attach: { publicKey: SM2_PUB, userId: UID },
      detach: { attachData: SM2_ATTACH },
      sign: { privateKey: SM2_D, message: 'abc',
        userId: UID },
      verify: { package: SM2_ATTACH_PKG, message: 'abc' }
    }
  });

  /* ------------------------------------------------------------ 点压缩 */
  CB.register({
    key: 'compress',
    cat: 'asym',
    title: '点压缩与解压',
    desc: 'SM2 / SM9 曲线点压缩（04||X||Y → 02/03||X）与解压（02/03||X → 04||X||Y）',
    help: [
      { title: '格式要求', items: [
        '未压缩公钥使用 04 开头的 HEX（65 字节），也接受省略 04 的 X||Y（64 字节）。',
        '压缩公钥使用 02 或 03 开头的 HEX（33 字节），末位表示 Y 的奇偶性。',
        '解压结果与原站一致，输出不带 04 前缀的 X||Y。'
      ] },
      { title: '曲线说明', items: [
        'SM2 使用 sm2p256v1；SM9 使用 GM/T 0044 推荐的 256 位 NB 曲线（y² = x³ + 5），解压通过模平方根还原 Y。',
        '输入点必须在该曲线上，否则会明确报错。'
      ] }
    ],
    state: {
      type: 'SM2',
      decompressPubkey: '', decompressPubkeyFormat: 'HEX',
      compressPubkey: '', compressPubkeyFormat: 'HEX'
    },
    formats: ['type', 'decompressPubkeyFormat', 'compressPubkeyFormat'],
    defaults: {},
    fields: [
      { name: 'type', label: '曲线类型', type: 'radio',
        options: [['SM2', 'SM2 曲线'], ['SM9', 'SM9 曲线']] },
      { name: 'decompressPubkey', label: '未压缩公钥（04 开头）', type: 'textarea', rows: 3,
        formatField: 'decompressPubkeyFormat', formats: [['HEX', '十六进制']],
        span: 2, placeholder: '04||X||Y' },
      { name: 'compressPubkey', label: '压缩公钥（02 / 03 开头）', type: 'textarea', rows: 3,
        formatField: 'compressPubkeyFormat', formats: [['HEX', '十六进制']],
        span: 2, placeholder: '02/03||X' }
    ],
    actions: [
      { name: 'compress', label: '压缩公钥', primary: true, run: async (ctx) => {
        const v = await ctx.api('/api/asym/compress/parse', {
          type: ctx.val('type'), compressType: 'compress',
          decompressPubkey: ctx.val('decompressPubkey'), compressPubkey: ''
        });
        ctx.set('compressPubkey', v); ctx.setResult('compressed', v); ctx.refresh();
        CB.toast('压缩成功', 'success');
      } },
      { name: 'decompress', label: '解压公钥', run: async (ctx) => {
        const v = await ctx.api('/api/asym/compress/parse', {
          type: ctx.val('type'), compressType: 'decompress',
          decompressPubkey: '', compressPubkey: ctx.val('compressPubkey')
        });
        ctx.set('decompressPubkey', v); ctx.setResult('decompressed', v); ctx.refresh();
        CB.toast('解压成功', 'success');
      } }
    ],
    results: [
      { name: 'compressed', label: '压缩公钥', type: 'textarea', rows: 2 },
      { name: 'decompressed', label: '解压结果（X||Y）', type: 'textarea', rows: 3 }
    ],
    samples: {
      compress: { type: 'SM2', decompressPubkey: SM2_PUB_FULL },
      decompress: { type: 'SM2', compressPubkey: SM2_COMPRESSED }
    }
  });
})();
