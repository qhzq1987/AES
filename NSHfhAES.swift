//
//  NSHfhAES.swift
//  BS5Kygd
//
//  Created by HeFahu on 2018/10/17.
//  Copyright © 2018年 HeFahu. All rights reserved.
//

import Foundation

extension String {
    
    func encrypt(with key: String, iv: String = ""/*为空，模式为ECB，否则为CBC模式*/) -> String {
        
        //是否为空？
        guard let inputData = self.data(using: .utf8), let keyData = key.data(using: .utf8) else {
            return ""
        }
        let operation = CCOperation(kCCEncrypt)
        //options类型
        let optionsVal = options(with: iv)
        //加密
        let tempData = willOperation(operation, with: optionsVal.ops, input: inputData, key: keyData, iv: optionsVal.iv)
        guard let resultData = tempData else {
            return ""
        }
        //返回
        return resultData.base64EncodedString(options: .lineLength64Characters)
    }
    
    func decrypt(with key: String, iv: String = ""/*为空，模式为ECB，否则为CBC模式*/) -> String {
        
        //是否为空？
        guard let inputData = Data(base64Encoded: self), let keyData = key.data(using: .utf8) else {
            return ""
        }
        let operation = CCOperation(kCCDecrypt)
        //options类型
        let optionsVal = options(with: iv)
        //解密
        let tempData = willOperation(operation, with: optionsVal.ops, input: inputData, key: keyData, iv: optionsVal.iv)
        guard let resultData = tempData else {
            return ""
        }
        //转成字符串
        guard let resultVal = String(data: resultData, encoding: .utf8) else {
            return ""
        }
        return resultVal
    }
    
    private func options(with iv: String) -> (ops: CCOptions, iv: Data?) {
        
        //options类型
        var options: CCOptions = CCOptions(kCCOptionPKCS7Padding + kCCOptionECBMode)
        //IV对象
        var ivData: Data!
        if "" != iv {
            if let tempData = iv.data(using: .utf8) {
                ivData = tempData
                options = CCOptions(kCCOptionPKCS7Padding)
            }
        }
        //返回
        return (options, ivData)
    }
    
    private func willOperation(_ op: CCOperation, with options: CCOptions, input: Data, key: Data, iv: Data?) -> Data? {
        
        //数据长度
        let dataLength: Int = input.count
        //输出
        var buffer = Data(count: dataLength + Int(kCCBlockSizeAES128))
        let bufferBytes = MBYTES(&buffer)
        //iv
        let ivBuffer = nil != iv ? BYTES(iv!) : nil
        //字节数量
        var numBytesEncrypted: Int = 0
        //加密
        let cryptStatus: CCCryptorStatus = CCCrypt(op, CCAlgorithm(kCCAlgorithmAES128),
                                                   options,
                                                   BYTES(key),
                                                   Int(kCCKeySizeAES128),
                                                   ivBuffer,
                                                   BYTES(input), dataLength,
                                                   bufferBytes, Int(buffer.count),
                                                   &numBytesEncrypted)
        //是否成功？
        if cryptStatus != kCCSuccess {
            print("cryptStatus = \(cryptStatus)")
            return nil
        }
        //最终长度
        buffer.count = numBytesEncrypted
        //返回
        return buffer
    }
    
    private func BYTES(_ d: Data) -> UnsafePointer<UInt8> {
        
        let result = d.withUnsafeBytes { (objBytes: UnsafePointer<UInt8>) -> UnsafePointer<UInt8> in
            return objBytes
        }
        return result
    }
    
    private func MBYTES(_ d: inout Data) -> UnsafeMutablePointer<UInt8> {
        
        let result = d.withUnsafeMutableBytes { (objBytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
            return objBytes
        }
        return result
    }
}
