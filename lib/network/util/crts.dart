/*
 * Copyright 2023 Hongen Wang All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:async';
import 'dart:core';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';
import 'package:proxypin/network/bin/configuration.dart';
import 'package:proxypin/network/util/cert/pkcs12.dart';
import 'package:proxypin/network/util/cert/emudhra_cas.dart';
import 'package:proxypin/network/util/cert/x509.dart';
import 'package:proxypin/network/util/logger.dart';
import 'package:proxypin/network/util/random.dart';
import 'package:proxypin/utils/lang.dart';

import 'cache.dart';
import 'cert/basic_constraints.dart';
import 'cert/cert_data.dart';
import 'cert/extension.dart';
import 'cert/key_usage.dart';
import 'crypto.dart';
import 'file_read.dart';

Future<void> main() async {
  await CertificateManager.getCertificateContext('www.jianshu.com');
}

enum StartState { uninitialized, initializing, initialized }

class CertificateManager {
  /// 证书缓存
  static final ExpiringCache<String, SecurityContext> _certificateMap =
      ExpiringCache<String, SecurityContext>(const Duration(minutes: 30));

  /// 远程服务器真实证书缓存(ssl验证失败时拉取, 用于生成更贴近真实证书的叶子证书)
  static final ExpiringCache<String, X509CertificateData> _remoteCertMap =
      ExpiringCache<String, X509CertificateData>(const Duration(minutes: 15));

  /// 服务端密钥
  static AsymmetricKeyPair _serverKeyPair = CryptoUtils.generateRSAKeyPair();

  /// ca证书
  static X509CertificateData? _caCert;

  /// ca私钥 (proxyPin RSA 模式)
  static RSAPrivateKey? _caPriKey;

  /// emudhra 模式的 secp384r1 EC 私钥
  static ECPrivateKey? _caEcPriKey;

  /// 随伪造叶子一起下发的颁发者链 PEM (emudhra 模式); proxyPin 模式为空
  static String _issuerChainPem = '';

  /// 当前签发模式: 'proxyPin' 使用内置自签 RSA 根, 'emudhra' 使用受损 eMudhra 中间 CA
  static String _caMode = 'emudhra';
  static String _emudhraCaId = '01';
  static EmudhraTrustPath _emudhraTrustPath = EmudhraTrustPath.emSign;

  static bool get useEmudhraCa => _caMode == 'emudhra';

  /// ca证书 subject DN 的原始 ASN.1 字节, 用作签发叶子证书的 issuer, 保证与 CA 二进制精确匹配
  static Uint8List? _caSubjectDnBytes;

  /// 是否初始化
  static StartState _state = StartState.uninitialized;
  static Completer<void> _initializationCompleter = Completer<void>();

  static SecurityContext? get(String host) {
    return _certificateMap[host];
  }

  static X509CertificateData? get caCert => _caCert;

  /// 当前签发模式: 'proxyPin' | 'emudhra'
  static String get caMode => _caMode;

  static String get emudhraCaId => _emudhraCaId;

  static EmudhraTrustPath get emudhraTrustPath => _emudhraTrustPath;

  /// 选择签发机构。mode='proxyPin'|'emudhra'; emudhraId 取 '01'..'08'; path 取 'emSign'|'aaa'。
  /// 变更后清空证书缓存, 下次请求按新配置重新初始化。
  static void selectSigningCa({String? mode, String? emudhraId, String? path}) {
    if (mode != null) _caMode = mode;
    if (emudhraId != null) _emudhraCaId = emudhraId;
    if (path != null) _emudhraTrustPath = EmudhraTrustPath.parse(path);
    cleanCache();
    _state = StartState.uninitialized;
  }

  /// 把「改用内置/导入的 proxyPin 根」写回配置, 否则重启后配置仍是 emudhra, 会静默切回 eMudhra 模式
  static Future<void> _persistProxyPinCaMode() async {
    _caMode = 'proxyPin';
    var config = await Configuration.instance;
    if (config.mitmCaMode == 'proxyPin') return;
    config.mitmCaMode = 'proxyPin';
    await config.flushConfig();
  }

  /// 清除缓存
  static void cleanCache() {
    _certificateMap.clear();
    _remoteCertMap.clear();
  }

  /// 获取域名自签名证书
  static Future<SecurityContext> getCertificateContext(String host) async {
    SecurityContext? securityContext = _certificateMap[host];
    if (securityContext != null) {
      return securityContext;
    }

    if (_state != StartState.initialized) {
      await initCAConfig();
    }

    return _createSecurityContext(host, remoteCert: _remoteCertMap[host]);
  }

  /// ssl验证失败时, 根据远程服务器真实证书重新生成叶子证书并刷新缓存
  ///
  /// [host] 域名
  /// [peerCertificate] 远程服务器证书(来自 [SecureSocket.peerCertificate])
  ///
  /// 返回 true 表示成功拉取并刷新了证书缓存; 若已经针对该域名拉取过, 或解析失败, 返回 false
  static Future<bool> generateByRemoteCert(String host, X509Certificate? peerCertificate) async {
    if (peerCertificate == null) {
      return false;
    }

    //同一域名只拉取一次, 避免重连风暴
    if (_remoteCertMap.containsKey(host)) {
      return false;
    }

    try {
      var remoteCert = X509Utils.x509CertificateFromPem(peerCertificate.pem);
      _remoteCertMap[host] = remoteCert;

      if (_state != StartState.initialized) {
        await initCAConfig();
      }

      _createSecurityContext(host, remoteCert: remoteCert);
      logger.d('regenerate certificate by remote cert for $host');
      return true;
    } catch (e, t) {
      logger.e('generate certificate by remote cert error: $host', error: e, stackTrace: t);
      return false;
    }
  }

  /// 生成域名叶子证书的 [SecurityContext] 并写入缓存
  static SecurityContext _createSecurityContext(String host, {X509CertificateData? remoteCert}) {
    var leafPem = _signLeaf(host, remoteCert: remoteCert);
    //emudhra 模式需随叶子一起下发颁发者链(中间 CA + 到受信锚点的交叉证书), 让无 root 设备走系统信任
    var chainPem = _issuerChainPem.isEmpty ? leafPem : "$leafPem\n$_issuerChainPem";
    var rsaPrivateKey = _serverKeyPair.privateKey as RSAPrivateKey;

    var securityContext = SecurityContext(withTrustedRoots: true)
      ..useCertificateChainBytes(chainPem.codeUnits)
      ..allowLegacyUnsafeRenegotiation = true
      ..usePrivateKeyBytes(CryptoUtils.encodeRSAPrivateKeyToPemPkcs1(rsaPrivateKey).codeUnits);

    _certificateMap[host] = securityContext;
    return securityContext;
  }

  /// 生成域名证书 PEM（仅证书，不含私钥）
  static Future<String> generateLeafCertificatePem(String host) async {
    if (_state != StartState.initialized) {
      await initCAConfig();
    }
    return _signLeaf(host);
  }

  /// 按当前签发模式 (emudhra ECDSA / proxyPin RSA) 为域名签发叶子证书 PEM
  static String _signLeaf(String host, {X509CertificateData? remoteCert}) {
    //默认 subject 模板, 以及仅包含域名本身的 SAN
    Map<String, String> x509Subject = {
      'C': 'CN',
      'ST': 'BJ',
      'L': 'Beijing',
      'O': 'Proxy',
      'OU': 'ProxyPin',
      'CN': host,
    };
    List<String> sans = [host];
    DateTime? notBefore;
    DateTime? notAfter;

    //存在远程真实证书时, 复制其 Subject、SAN、有效期, 以通过客户端严格校验
    if (remoteCert != null) {
      x509Subject = _remoteSubject(remoteCert) ?? x509Subject;
      sans = _remoteSans(remoteCert) ?? sans;
      notBefore = remoteCert.validity.notBefore;
      notAfter = remoteCert.validity.notAfter;
    }

    var serverPubKey = _serverKeyPair.publicKey as RSAPublicKey;
    var serialNumber = Random().nextInt(1000000).toString();

    //emudhra 模式下私钥缺失通常意味着 CA 资源没打进包里, 直接报错比空断言崩溃更可定位
    if (useEmudhraCa) {
      var ecPriKey = _caEcPriKey;
      if (_caCert == null || ecPriKey == null) {
        throw StateError('eMudhra 模式未加载 CA (id=$_emudhraCaId path=$_emudhraTrustPath), 请在设置里重新选择签发 CA');
      }
      return X509Utils.generateServerCertificate(_caCert!, serverPubKey, ecPriKey, 36,
          sans: sans,
          serialNumber: serialNumber,
          subject: x509Subject,
          issuerRawBytes: _caSubjectDnBytes,
          notBefore: notBefore,
          notAfter: notAfter);
    }

    var rsaPriKey = _caPriKey;
    if (_caCert == null || rsaPriKey == null) {
      throw StateError('ProxyPin 根证书/私钥未加载, 请在设置里重新生成或导入 CA');
    }
    return X509Utils.generateSelfSignedCertificate(_caCert!, serverPubKey, rsaPriKey, 36,
        sans: sans,
        serialNumber: serialNumber,
        subject: x509Subject,
        issuerRawBytes: _caSubjectDnBytes,
        notBefore: notBefore,
        notAfter: notAfter);
  }

  /// 生成证书 (proxyPin RSA 根签发, 兼容旧调用)
  ///
  /// [remoteCert] 远程服务器真实证书, 若提供则复制其 Subject、SAN、有效期, 以通过客户端严格校验
  static String generate(X509CertificateData caRoot, RSAPublicKey serverPubKey, RSAPrivateKey caPriKey, String host,
      {X509CertificateData? remoteCert}) {
    Map<String, String> x509Subject = {
      'C': 'CN',
      'ST': 'BJ',
      'L': 'Beijing',
      'O': 'Proxy',
      'OU': 'ProxyPin',
      'CN': host,
    };
    List<String> sans = [host];
    DateTime? notBefore;
    DateTime? notAfter;

    if (remoteCert != null) {
      x509Subject = _remoteSubject(remoteCert) ?? x509Subject;
      sans = _remoteSans(remoteCert) ?? sans;
      notBefore = remoteCert.validity.notBefore;
      notAfter = remoteCert.validity.notAfter;
    }

    return X509Utils.generateSelfSignedCertificate(caRoot, serverPubKey, caPriKey, 36,
        sans: sans,
        serialNumber: Random().nextInt(1000000).toString(),
        subject: x509Subject,
        issuerRawBytes: _caSubjectDnBytes,
        notBefore: notBefore,
        notAfter: notAfter);
  }

  /// 提取远程证书的 subject (key 为 OID 字符串, 如 2.5.4.3=CN), 整体替换默认模板避免 CN 重复; 为空返回 null
  static Map<String, String>? _remoteSubject(X509CertificateData remoteCert) {
    Map<String, String> subject = {};
    remoteCert.subject.forEach((key, value) {
      if (value != null && value.isNotEmpty) {
        subject[key] = value;
      }
    });
    return subject.isEmpty ? null : subject;
  }

  /// 提取远程证书的 DNS 类型 SAN, 过滤 DirName 等非 DNS 条目; 为空返回 null
  static List<String>? _remoteSans(X509CertificateData remoteCert) {
    var sans = remoteCert.subjectAlternativNames?.where((e) => !e.startsWith('DirName:')).toList();
    return (sans == null || sans.isEmpty) ? null : sans;
  }

  /// 获取证书主题hash
  static Future<String> systemCertificateName() async {
    if (_state != StartState.initialized) {
      await initCAConfig();
    }

    var subject = caCert!.subject;
    return '${X509Utils.getSubjectHashName(subject)}.0';
  }

  //重新生成根证书
  static Future<void> generateNewRootCA() async {
    if (_state != StartState.initialized) {
      await initCAConfig();
    }

    var generateRSAKeyPair = CryptoUtils.generateRSAKeyPair();
    var serverPubKey = generateRSAKeyPair.publicKey as RSAPublicKey;
    var serverPriKey = generateRSAKeyPair.privateKey as RSAPrivateKey;

    //根据CA证书subject来动态生成目标服务器证书的issuer和subject
    Map<String, String> x509Subject = {
      'C': 'CN',
      'ST': 'BJ',
      'L': 'Beijing',
      'O': 'Proxy',
      'OU': 'ProxyPin',
    };
    x509Subject['CN'] = 'ProxyPin CA (${DateTime.now().dateFormat()},${RandomUtil.randomString(6).toUpperCase()})';

    var csrPem = X509Utils.generateSelfSignedCertificate(
      _caCert!,
      serverPubKey,
      serverPriKey,
      825,
      sans: [x509Subject['CN']!],
      serialNumber: DateTime.now().millisecondsSinceEpoch.toString(),
      issuer: x509Subject,
      subject: x509Subject,
      keyUsage: ExtensionKeyUsage(ExtensionKeyUsage.keyCertSign),
      extKeyUsage: [ExtendedKeyUsage.SERVER_AUTH],
      basicConstraints: BasicConstraints(isCA: true),
    );

    //重新写入根证书
    var caFile = await certificateFile();
    await caFile.writeAsString(csrPem);

    //私钥
    var serverPriKeyPem = CryptoUtils.encodeRSAPrivateKeyToPem(serverPriKey);
    var keyFile = await privateKeyFile();
    await keyFile.writeAsString(serverPriKeyPem);
    await _persistProxyPinCaMode();
    cleanCache();
    _state = StartState.uninitialized;
  }

  ///重置默认根证书
  static Future<void> resetDefaultRootCA() async {
    var caFile = await certificateFile();
    await caFile.delete();

    var keyFile = await privateKeyFile();
    await keyFile.delete();
    await _persistProxyPinCaMode();
    cleanCache();
    _state = StartState.uninitialized;
    initCAConfig();
  }

  static Future<void> initCAConfig() async {
    if (_state == StartState.initialized || _state == StartState.initializing) {
      return _initializationCompleter.future;
    }

    var startTime = DateTime.now().millisecondsSinceEpoch;

    _state = StartState.initializing;
    _initializationCompleter = Completer<void>();

    try {
      _serverKeyPair = CryptoUtils.generateRSAKeyPair();

      if (useEmudhraCa) {
        //emudhra 模式: 载入受损中间 CA + secp384r1 私钥 + 到系统信任锚点的颁发者链
        var ca = EmudhraCas.byId(_emudhraCaId) ?? EmudhraCas.defaultCa;
        var material = await EmudhraCaLoader.load(ca, _emudhraTrustPath);
        _caCert = material.ca;
        _caSubjectDnBytes = material.subjectDnBytes;
        _caEcPriKey = material.key;
        _caPriKey = null;
        _issuerChainPem = material.chainPem;
      } else {
        //proxyPin 模式: 内置/用户自签 RSA 根, 仅下发叶子 (无 root 设备需手动安装该根)
        var caPemFile = await certificateFile();
        var caPem = await caPemFile.readAsString();
        _caCert = X509Utils.x509CertificateFromPem(caPem);
        //提取 CA subject DN 原始字节, 供签发叶子证书时作为 issuer, 保证与 CA 二进制精确匹配(兼容 iOS 严格校验)
        _caSubjectDnBytes = X509Utils.subjectDnBytesFromPem(caPem);
        var keyFile = await privateKeyFile();
        _caPriKey = CryptoUtils.rsaPrivateKeyFromPem(await keyFile.readAsString());
        _caEcPriKey = null;
        _issuerChainPem = '';
      }

      _state = StartState.initialized;
      _initializationCompleter.complete();
    } catch (e) {
      logger.e('init ca config error:$e');
      _state = StartState.uninitialized;
      _initializationCompleter.completeError(e);
    }

    logger.d('init ca config end cost:${DateTime.now().millisecondsSinceEpoch - startTime}');

    return _initializationCompleter.future;
  }

  /// 证书文件
  static Future<File> certificateFile() async {
    final String appPath = await getApplicationSupportDirectory().then((value) => value.path);
    var caFile = File("$appPath${Platform.pathSeparator}ca.crt");
    if (!(await caFile.exists())) {
      var body = await FileRead.read('assets/certs/ca.crt');
      await caFile.writeAsBytes(body.buffer.asUint8List());
    }

    return caFile;
  }

  ///证书pem格式内容
  static Future<String> certificatePem() async {
    var caFile = await certificateFile();
    return caFile.readAsString();
  }

  /// 私钥文件
  static Future<File> privateKeyFile() async {
    final String appPath = await getApplicationSupportDirectory().then((value) => value.path);
    var caFile = File("$appPath${Platform.pathSeparator}ca_key.pem");
    if (!(await caFile.exists())) {
      var body = await FileRead.read('assets/certs/ca_key.pem');
      await caFile.writeAsBytes(body.buffer.asUint8List());
    }

    return caFile;
  }

  ///生成 p12文件
  static Future<Uint8List> generatePkcs12(String? password) async {
    var caFile = await CertificateManager.certificateFile();
    var keyFile = await CertificateManager.privateKeyFile();
    return Pkcs12.generatePkcs12(await keyFile.readAsString(), [await caFile.readAsString()], password: password);
  }

  ///import p12文件
  static Future<void> importPkcs12(Uint8List pkcs12, String? password) async {
    var decodePkcs12 = Pkcs12.parsePkcs12(pkcs12, password: password);

    var caFile = await CertificateManager.certificateFile();
    var keyFile = await CertificateManager.privateKeyFile();
    if (decodePkcs12.length != 2) {
      throw Exception('Invalid pkcs12 file');
    }

    await keyFile.writeAsString(decodePkcs12[0]);
    await caFile.writeAsString(decodePkcs12[1]);

    await _persistProxyPinCaMode();
    cleanCache();
    _state = StartState.uninitialized;
    initCAConfig();
  }

  /// 获取证书详细信息
  static Future<X509CertificateData> getCertificateDetails() async {
    if (_state != StartState.initialized) {
      await initCAConfig();
    }
    return caCert!;
  }
}
