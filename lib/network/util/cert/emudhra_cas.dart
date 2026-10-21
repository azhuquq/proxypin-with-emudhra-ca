import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:proxypin/network/util/cert/cert_data.dart';
import 'package:proxypin/network/util/cert/x509.dart';
import 'package:proxypin/network/util/crypto.dart';
import 'package:proxypin/network/util/file_read.dart';

/// 中间 CA 使用的信任路径: emSign 根(交叉签名到 emSign ECC Root CA - G3) 或 Sectigo AAA 根
enum EmudhraTrustPath {
  emSign,
  aaa;

  static EmudhraTrustPath parse(String? value) =>
      value == 'aaa' ? EmudhraTrustPath.aaa : EmudhraTrustPath.emSign;
}

/// 一张受损的 eMudhra 中间 CA(可用作 MITM 签发机构)
class EmudhraCa {
  final String id;
  final String name;
  final String kind;
  final String generation;
  final String caType;

  const EmudhraCa(this.id, this.name, this.kind, this.generation, this.caType);

  String get assetDir => 'assets/certs/emudhra/$id';

  @override
  String toString() => name;
}

/// 8 张受损 eMudhra 中间 CA 的目录(与 assets/certs/emudhra/manifest.json 一致)
class EmudhraCas {
  static const List<EmudhraCa> list = [
    EmudhraCa('01', 'EM DV TLS CA - G3B', 'DV', 'G3B', 'TLS'),
    EmudhraCa('02', 'EM OV TLS CA - G3B', 'OV', 'G3B', 'TLS'),
    EmudhraCa('03', 'EM EV TLS CA - G3B', 'EV', 'G3B', 'TLS'),
    EmudhraCa('04', 'EM DV TLS CA - G3C', 'DV', 'G3C', 'TLS'),
    EmudhraCa('05', 'EM OV TLS CA - G3C', 'OV', 'G3C', 'TLS'),
    EmudhraCa('06', 'EM EV TLS CA - G3C', 'EV', 'G3C', 'TLS'),
    EmudhraCa('07', 'EM OV CS CA - G3B', 'OV', 'G3B', 'CS'),
    EmudhraCa('08', 'EM OV CS CA - G3C', 'OV', 'G3C', 'CS'),
  ];

  static EmudhraCa? byId(String? id) {
    for (var ca in list) {
      if (ca.id == id) {
        return ca;
      }
    }
    return null;
  }

  /// 默认签发机构: EM DV TLS CA - G3B (id=01)
  static EmudhraCa get defaultCa => list.first;
}

/// 载入后的签发材料: 中间 CA 证书、其 secp384r1 私钥、subject DN 原始字节、以及信任路径的颁发者链
class EmudhraSigningMaterial {
  final X509CertificateData ca;
  final ECPrivateKey key;
  final Uint8List subjectDnBytes;

  /// 去掉叶子后的颁发者链 PEM (在伪造叶子之后随 TLS 一起下发)
  final String chainPem;

  const EmudhraSigningMaterial(this.ca, this.key, this.subjectDnBytes, this.chainPem);
}

class EmudhraCaLoader {
  static Future<EmudhraSigningMaterial> load(EmudhraCa ca, EmudhraTrustPath path) async {
    var caPem = await FileRead.readAsString('${ca.assetDir}/ca.pem');
    var keyPem = await FileRead.readAsString('${ca.assetDir}/key.pem');
    var chainPem =
        await FileRead.readAsString('${ca.assetDir}/${path == EmudhraTrustPath.emSign ? 'chain_emsign' : 'chain_aaa'}.pem');

    return EmudhraSigningMaterial(
      X509Utils.x509CertificateFromPem(caPem),
      CryptoUtils.ecPrivateKeyFromPem(keyPem),
      X509Utils.subjectDnBytesFromPem(caPem),
      chainPem,
    );
  }
}
