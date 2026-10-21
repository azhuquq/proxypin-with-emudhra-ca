import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:proxypin/network/util/cert/emudhra_cas.dart';
import 'package:proxypin/network/util/cert/x509.dart';
import 'package:proxypin/network/util/crypto.dart';

/// 用受损 eMudhra 中间 CA 的 EC 私钥伪造叶子证书, 再用 openssl 沿真实信任链校验。
/// 覆盖 8 张 CA 的两条信任路径 (emSign / Sectigo AAA), 模拟无 root 设备上的 MITM 结果。
void main() {
  const root = 'assets/certs/emudhra';
  const roots = '$root/roots';
  final eccRoot = '$roots/emsign-ecc-root-g3.pem';
  final csRoot = '$roots/emsign-cs-root-g3.pem';
  final aaaRoot = '$roots/aaa.pem';

  // 服务器叶子公钥复用同一把 RSA, 只需生成一次
  final serverKeyPair = CryptoUtils.generateRSAKeyPair();
  final serverPub = serverKeyPair.publicKey as RSAPublicKey;

  for (final ca in EmudhraCas.list) {
    final emSignAnchor = ca.caType == 'CS' ? csRoot : eccRoot;

    test('SPKI parses & key matches cert for ${ca.name}', () {
      final caPem = File('$root/${ca.id}/ca.pem').readAsStringSync();
      final key = CryptoUtils.ecPrivateKeyFromPem(File('$root/${ca.id}/key.pem').readAsStringSync());
      final cert = X509Utils.x509CertificateFromPem(caPem);
      expect(cert.signatureAlgorithm, isNotEmpty);
      expect(key.d != null && key.d! > BigInt.zero && key.d! < BigInt.from(256), isTrue,
          reason: 'expected a small secp384r1 scalar 1..255');
    });

    for (final path in EmudhraTrustPath.values) {
      final isAaa = path == EmudhraTrustPath.aaa;
      final anchor = isAaa ? aaaRoot : emSignAnchor;

      test('forged leaf validates via ${isAaa ? 'AAA' : 'emSign'} for ${ca.name}', () async {
        final caPem = File('$root/${ca.id}/ca.pem').readAsStringSync();
        final key = CryptoUtils.ecPrivateKeyFromPem(File('$root/${ca.id}/key.pem').readAsStringSync());
        final chain = File('$root/${ca.id}/${isAaa ? 'chain_aaa' : 'chain_emsign'}.pem').readAsStringSync();
        final caData = X509Utils.x509CertificateFromPem(caPem);
        final dn = X509Utils.subjectDnBytesFromPem(caPem);

        final leaf = X509Utils.generateServerCertificate(caData, serverPub, key, 365,
            sans: ['example.com'], subject: {'CN': 'example.com'}, issuerRawBytes: dn);

        // 模拟 TLS 下发: 伪造叶子 + 颁发者链拼接为一份 PEM, 与真实 MITM 完全一致
        final served = leaf + "\n" + chain;
        final tmp = Directory.systemTemp.createTempSync('emudhra');
        final leafFile = File('${tmp.path}/served.pem')..writeAsStringSync(served);

        final res = await Process.run('openssl', [
          'verify',
          '-CAfile',
          anchor,
          '-untrusted',
          leafFile.path,
          leafFile.path
        ]);
        final out = '${res.stdout}${res.stderr}';
        tmp.deleteSync(recursive: true);

        expect(res.exitCode, 0, reason: 'openssl verify failed: $out');
        expect(out, contains(': OK'));
      });
    }
  }
}
