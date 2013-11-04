package kr.co.bizframe.crypto.ciphers;

import kr.co.bizframe.crypto.BlockCipher;
import kr.co.bizframe.crypto.CipherParameters;
import kr.co.bizframe.crypto.DataLengthException;
import kr.co.bizframe.crypto.params.KeyParameter;

public class ARIAEngine implements BlockCipher {

	private static final byte[][] S1 = new byte[][] {
			{ (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2,
					(byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30,
					(byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe,
					(byte) 0xd7, (byte) 0xab, (byte) 0x76 },
			{ (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa,
					(byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad,
					(byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c,
					(byte) 0xa4, (byte) 0x72, (byte) 0xc0 },
			{ (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36,
					(byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34,
					(byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71,
					(byte) 0xd8, (byte) 0x31, (byte) 0x15 },
			{ (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18,
					(byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07,
					(byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb,
					(byte) 0x27, (byte) 0xb2, (byte) 0x75 },
			{ (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b,
					(byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52,
					(byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29,
					(byte) 0xe3, (byte) 0x2f, (byte) 0x84 },
			{ (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20,
					(byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a,
					(byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a,
					(byte) 0x4c, (byte) 0x58, (byte) 0xcf },
			{ (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43,
					(byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45,
					(byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50,
					(byte) 0x3c, (byte) 0x9f, (byte) 0xa8 },
			{ (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92,
					(byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc,
					(byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10,
					(byte) 0xff, (byte) 0xf3, (byte) 0xd2 },
			{ (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f,
					(byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4,
					(byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64,
					(byte) 0x5d, (byte) 0x19, (byte) 0x73 },
			{ (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22,
					(byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46,
					(byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde,
					(byte) 0x5e, (byte) 0x0b, (byte) 0xdb },
			{ (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49,
					(byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2,
					(byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91,
					(byte) 0x95, (byte) 0xe4, (byte) 0x79 },
			{ (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d,
					(byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c,
					(byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65,
					(byte) 0x7a, (byte) 0xae, (byte) 0x08 },
			{ (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c,
					(byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8,
					(byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b,
					(byte) 0xbd, (byte) 0x8b, (byte) 0x8a },
			{ (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48,
					(byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61,
					(byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86,
					(byte) 0xc1, (byte) 0x1d, (byte) 0x9e },
			{ (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69,
					(byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b,
					(byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce,
					(byte) 0x55, (byte) 0x28, (byte) 0xdf },
			{ (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf,
					(byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41,
					(byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0,
					(byte) 0x54, (byte) 0xbb, (byte) 0x16 } };

	private static final byte[][] S2 = new byte[][] {
			{ (byte) 0xe2, (byte) 0x4e, (byte) 0x54, (byte) 0xfc, (byte) 0x94,
					(byte) 0xc2, (byte) 0x4a, (byte) 0xcc, (byte) 0x62,
					(byte) 0x0d, (byte) 0x6a, (byte) 0x46, (byte) 0x3c,
					(byte) 0x4d, (byte) 0x8b, (byte) 0xd1 },
			{ (byte) 0x5e, (byte) 0xfa, (byte) 0x64, (byte) 0xcb, (byte) 0xb4,
					(byte) 0x97, (byte) 0xbe, (byte) 0x2b, (byte) 0xbc,
					(byte) 0x77, (byte) 0x2e, (byte) 0x03, (byte) 0xd3,
					(byte) 0x19, (byte) 0x59, (byte) 0xc1 },
			{ (byte) 0x1d, (byte) 0x06, (byte) 0x41, (byte) 0x6b, (byte) 0x55,
					(byte) 0xf0, (byte) 0x99, (byte) 0x69, (byte) 0xea,
					(byte) 0x9c, (byte) 0x18, (byte) 0xae, (byte) 0x63,
					(byte) 0xdf, (byte) 0xe7, (byte) 0xbb },
			{ (byte) 0x00, (byte) 0x73, (byte) 0x66, (byte) 0xfb, (byte) 0x96,
					(byte) 0x4c, (byte) 0x85, (byte) 0xe4, (byte) 0x3a,
					(byte) 0x09, (byte) 0x45, (byte) 0xaa, (byte) 0x0f,
					(byte) 0xee, (byte) 0x10, (byte) 0xeb },
			{ (byte) 0x2d, (byte) 0x7f, (byte) 0xf4, (byte) 0x29, (byte) 0xac,
					(byte) 0xcf, (byte) 0xad, (byte) 0x91, (byte) 0x8d,
					(byte) 0x78, (byte) 0xc8, (byte) 0x95, (byte) 0xf9,
					(byte) 0x2f, (byte) 0xce, (byte) 0xcd },
			{ (byte) 0x08, (byte) 0x7a, (byte) 0x88, (byte) 0x38, (byte) 0x5c,
					(byte) 0x83, (byte) 0x2a, (byte) 0x28, (byte) 0x47,
					(byte) 0xdb, (byte) 0xb8, (byte) 0xc7, (byte) 0x93,
					(byte) 0xa4, (byte) 0x12, (byte) 0x53 },
			{ (byte) 0xff, (byte) 0x87, (byte) 0x0e, (byte) 0x31, (byte) 0x36,
					(byte) 0x21, (byte) 0x58, (byte) 0x48, (byte) 0x01,
					(byte) 0x8e, (byte) 0x37, (byte) 0x74, (byte) 0x32,
					(byte) 0xca, (byte) 0xe9, (byte) 0xb1 },
			{ (byte) 0xb7, (byte) 0xab, (byte) 0x0c, (byte) 0xd7, (byte) 0xc4,
					(byte) 0x56, (byte) 0x42, (byte) 0x26, (byte) 0x07,
					(byte) 0x98, (byte) 0x60, (byte) 0xd9, (byte) 0xb6,
					(byte) 0xb9, (byte) 0x11, (byte) 0x40 },
			{ (byte) 0xec, (byte) 0x20, (byte) 0x8c, (byte) 0xbd, (byte) 0xa0,
					(byte) 0xc9, (byte) 0x84, (byte) 0x04, (byte) 0x49,
					(byte) 0x23, (byte) 0xf1, (byte) 0x4f, (byte) 0x50,
					(byte) 0x1f, (byte) 0x13, (byte) 0xdc },
			{ (byte) 0xd8, (byte) 0xc0, (byte) 0x9e, (byte) 0x57, (byte) 0xe3,
					(byte) 0xc3, (byte) 0x7b, (byte) 0x65, (byte) 0x3b,
					(byte) 0x02, (byte) 0x8f, (byte) 0x3e, (byte) 0xe8,
					(byte) 0x25, (byte) 0x92, (byte) 0xe5 },
			{ (byte) 0x15, (byte) 0xdd, (byte) 0xfd, (byte) 0x17, (byte) 0xa9,
					(byte) 0xbf, (byte) 0xd4, (byte) 0x9a, (byte) 0x7e,
					(byte) 0xc5, (byte) 0x39, (byte) 0x67, (byte) 0xfe,
					(byte) 0x76, (byte) 0x9d, (byte) 0x43 },
			{ (byte) 0xa7, (byte) 0xe1, (byte) 0xd0, (byte) 0xf5, (byte) 0x68,
					(byte) 0xf2, (byte) 0x1b, (byte) 0x34, (byte) 0x70,
					(byte) 0x05, (byte) 0xa3, (byte) 0x8a, (byte) 0xd5,
					(byte) 0x79, (byte) 0x86, (byte) 0xa8 },
			{ (byte) 0x30, (byte) 0xc6, (byte) 0x51, (byte) 0x4b, (byte) 0x1e,
					(byte) 0xa6, (byte) 0x27, (byte) 0xf6, (byte) 0x35,
					(byte) 0xd2, (byte) 0x6e, (byte) 0x24, (byte) 0x16,
					(byte) 0x82, (byte) 0x5f, (byte) 0xda },
			{ (byte) 0xe6, (byte) 0x75, (byte) 0xa2, (byte) 0xef, (byte) 0x2c,
					(byte) 0xb2, (byte) 0x1c, (byte) 0x9f, (byte) 0x5d,
					(byte) 0x6f, (byte) 0x80, (byte) 0x0a, (byte) 0x72,
					(byte) 0x44, (byte) 0x9b, (byte) 0x6c },
			{ (byte) 0x90, (byte) 0x0b, (byte) 0x5b, (byte) 0x33, (byte) 0x7d,
					(byte) 0x5a, (byte) 0x52, (byte) 0xf3, (byte) 0x61,
					(byte) 0xa1, (byte) 0xf7, (byte) 0xb0, (byte) 0xd6,
					(byte) 0x3f, (byte) 0x7c, (byte) 0x6d },
			{ (byte) 0xed, (byte) 0x14, (byte) 0xe0, (byte) 0xa5, (byte) 0x3d,
					(byte) 0x22, (byte) 0xb3, (byte) 0xf8, (byte) 0x89,
					(byte) 0xde, (byte) 0x71, (byte) 0x1a, (byte) 0xaf,
					(byte) 0xba, (byte) 0xb5, (byte) 0x81 } };

	private static final byte[][] X1 = new byte[][] {
			{ (byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30,
					(byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf,
					(byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81,
					(byte) 0xf3, (byte) 0xd7, (byte) 0xfb },
			{ (byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b,
					(byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34,
					(byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4,
					(byte) 0xde, (byte) 0xe9, (byte) 0xcb },
			{ (byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6,
					(byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee,
					(byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42,
					(byte) 0xfa, (byte) 0xc3, (byte) 0x4e },
			{ (byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28,
					(byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76,
					(byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d,
					(byte) 0x8b, (byte) 0xd1, (byte) 0x25 },
			{ (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86,
					(byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4,
					(byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d,
					(byte) 0x65, (byte) 0xb6, (byte) 0x92 },
			{ (byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd,
					(byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e,
					(byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7,
					(byte) 0x8d, (byte) 0x9d, (byte) 0x84 },
			{ (byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c,
					(byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7,
					(byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8,
					(byte) 0xb3, (byte) 0x45, (byte) 0x06 },
			{ (byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca,
					(byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1,
					(byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01,
					(byte) 0x13, (byte) 0x8a, (byte) 0x6b },
			{ (byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f,
					(byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97,
					(byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0,
					(byte) 0xb4, (byte) 0xe6, (byte) 0x73 },
			{ (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7,
					(byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2,
					(byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c,
					(byte) 0x75, (byte) 0xdf, (byte) 0x6e },
			{ (byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d,
					(byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f,
					(byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa,
					(byte) 0x18, (byte) 0xbe, (byte) 0x1b },
			{ (byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6,
					(byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a,
					(byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78,
					(byte) 0xcd, (byte) 0x5a, (byte) 0xf4 },
			{ (byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88,
					(byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1,
					(byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27,
					(byte) 0x80, (byte) 0xec, (byte) 0x5f },
			{ (byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19,
					(byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d,
					(byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93,
					(byte) 0xc9, (byte) 0x9c, (byte) 0xef },
			{ (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae,
					(byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8,
					(byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83,
					(byte) 0x53, (byte) 0x99, (byte) 0x61 },
			{ (byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba,
					(byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1,
					(byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55,
					(byte) 0x21, (byte) 0x0c, (byte) 0x7d } };

	private static final byte[][] X2 = new byte[][] {
			{ (byte) 0x30, (byte) 0x68, (byte) 0x99, (byte) 0x1b, (byte) 0x87,
					(byte) 0xb9, (byte) 0x21, (byte) 0x78, (byte) 0x50,
					(byte) 0x39, (byte) 0xdb, (byte) 0xe1, (byte) 0x72,
					(byte) 0x09, (byte) 0x62, (byte) 0x3c },
			{ (byte) 0x3e, (byte) 0x7e, (byte) 0x5e, (byte) 0x8e, (byte) 0xf1,
					(byte) 0xa0, (byte) 0xcc, (byte) 0xa3, (byte) 0x2a,
					(byte) 0x1d, (byte) 0xfb, (byte) 0xb6, (byte) 0xd6,
					(byte) 0x20, (byte) 0xc4, (byte) 0x8d },
			{ (byte) 0x81, (byte) 0x65, (byte) 0xf5, (byte) 0x89, (byte) 0xcb,
					(byte) 0x9d, (byte) 0x77, (byte) 0xc6, (byte) 0x57,
					(byte) 0x43, (byte) 0x56, (byte) 0x17, (byte) 0xd4,
					(byte) 0x40, (byte) 0x1a, (byte) 0x4d },
			{ (byte) 0xc0, (byte) 0x63, (byte) 0x6c, (byte) 0xe3, (byte) 0xb7,
					(byte) 0xc8, (byte) 0x64, (byte) 0x6a, (byte) 0x53,
					(byte) 0xaa, (byte) 0x38, (byte) 0x98, (byte) 0x0c,
					(byte) 0xf4, (byte) 0x9b, (byte) 0xed },
			{ (byte) 0x7f, (byte) 0x22, (byte) 0x76, (byte) 0xaf, (byte) 0xdd,
					(byte) 0x3a, (byte) 0x0b, (byte) 0x58, (byte) 0x67,
					(byte) 0x88, (byte) 0x06, (byte) 0xc3, (byte) 0x35,
					(byte) 0x0d, (byte) 0x01, (byte) 0x8b },
			{ (byte) 0x8c, (byte) 0xc2, (byte) 0xe6, (byte) 0x5f, (byte) 0x02,
					(byte) 0x24, (byte) 0x75, (byte) 0x93, (byte) 0x66,
					(byte) 0x1e, (byte) 0xe5, (byte) 0xe2, (byte) 0x54,
					(byte) 0xd8, (byte) 0x10, (byte) 0xce },
			{ (byte) 0x7a, (byte) 0xe8, (byte) 0x08, (byte) 0x2c, (byte) 0x12,
					(byte) 0x97, (byte) 0x32, (byte) 0xab, (byte) 0xb4,
					(byte) 0x27, (byte) 0x0a, (byte) 0x23, (byte) 0xdf,
					(byte) 0xef, (byte) 0xca, (byte) 0xd9 },
			{ (byte) 0xb8, (byte) 0xfa, (byte) 0xdc, (byte) 0x31, (byte) 0x6b,
					(byte) 0xd1, (byte) 0xad, (byte) 0x19, (byte) 0x49,
					(byte) 0xbd, (byte) 0x51, (byte) 0x96, (byte) 0xee,
					(byte) 0xe4, (byte) 0xa8, (byte) 0x41 },
			{ (byte) 0xda, (byte) 0xff, (byte) 0xcd, (byte) 0x55, (byte) 0x86,
					(byte) 0x36, (byte) 0xbe, (byte) 0x61, (byte) 0x52,
					(byte) 0xf8, (byte) 0xbb, (byte) 0x0e, (byte) 0x82,
					(byte) 0x48, (byte) 0x69, (byte) 0x9a },
			{ (byte) 0xe0, (byte) 0x47, (byte) 0x9e, (byte) 0x5c, (byte) 0x04,
					(byte) 0x4b, (byte) 0x34, (byte) 0x15, (byte) 0x79,
					(byte) 0x26, (byte) 0xa7, (byte) 0xde, (byte) 0x29,
					(byte) 0xae, (byte) 0x92, (byte) 0xd7 },
			{ (byte) 0x84, (byte) 0xe9, (byte) 0xd2, (byte) 0xba, (byte) 0x5d,
					(byte) 0xf3, (byte) 0xc5, (byte) 0xb0, (byte) 0xbf,
					(byte) 0xa4, (byte) 0x3b, (byte) 0x71, (byte) 0x44,
					(byte) 0x46, (byte) 0x2b, (byte) 0xfc },
			{ (byte) 0xeb, (byte) 0x6f, (byte) 0xd5, (byte) 0xf6, (byte) 0x14,
					(byte) 0xfe, (byte) 0x7c, (byte) 0x70, (byte) 0x5a,
					(byte) 0x7d, (byte) 0xfd, (byte) 0x2f, (byte) 0x18,
					(byte) 0x83, (byte) 0x16, (byte) 0xa5 },
			{ (byte) 0x91, (byte) 0x1f, (byte) 0x05, (byte) 0x95, (byte) 0x74,
					(byte) 0xa9, (byte) 0xc1, (byte) 0x5b, (byte) 0x4a,
					(byte) 0x85, (byte) 0x6d, (byte) 0x13, (byte) 0x07,
					(byte) 0x4f, (byte) 0x4e, (byte) 0x45 },
			{ (byte) 0xb2, (byte) 0x0f, (byte) 0xc9, (byte) 0x1c, (byte) 0xa6,
					(byte) 0xbc, (byte) 0xec, (byte) 0x73, (byte) 0x90,
					(byte) 0x7b, (byte) 0xcf, (byte) 0x59, (byte) 0x8f,
					(byte) 0xa1, (byte) 0xf9, (byte) 0x2d },
			{ (byte) 0xf2, (byte) 0xb1, (byte) 0x00, (byte) 0x94, (byte) 0x37,
					(byte) 0x9f, (byte) 0xd0, (byte) 0x2e, (byte) 0x9c,
					(byte) 0x6e, (byte) 0x28, (byte) 0x3f, (byte) 0x80,
					(byte) 0xf0, (byte) 0x3d, (byte) 0xd3 },
			{ (byte) 0x25, (byte) 0x8a, (byte) 0xb5, (byte) 0xe7, (byte) 0x42,
					(byte) 0xb3, (byte) 0xc7, (byte) 0xea, (byte) 0xf7,
					(byte) 0x4c, (byte) 0x11, (byte) 0x33, (byte) 0x03,
					(byte) 0xa2, (byte) 0xac, (byte) 0x60 } };

	private static final byte[][] C = {
			{ (byte) 0x51, (byte) 0x7c, (byte) 0xc1, (byte) 0xb7, (byte) 0x27,
					(byte) 0x22, (byte) 0x0a, (byte) 0x94, (byte) 0xfe,
					(byte) 0x13, (byte) 0xab, (byte) 0xe8, (byte) 0xfa,
					(byte) 0x9a, (byte) 0x6e, (byte) 0xe0 },
			{ (byte) 0x6d, (byte) 0xb1, (byte) 0x4a, (byte) 0xcc, (byte) 0x9e,
					(byte) 0x21, (byte) 0xc8, (byte) 0x20, (byte) 0xff,
					(byte) 0x28, (byte) 0xb1, (byte) 0xd5, (byte) 0xef,
					(byte) 0x5d, (byte) 0xe2, (byte) 0xb0 },
			{ (byte) 0xdb, (byte) 0x92, (byte) 0x37, (byte) 0x1d, (byte) 0x21,
					(byte) 0x26, (byte) 0xe9, (byte) 0x70, (byte) 0x03,
					(byte) 0x24, (byte) 0x97, (byte) 0x75, (byte) 0x04,
					(byte) 0xe8, (byte) 0xc9, (byte) 0x0e } };

	private int nRounds;
	private byte[][] ek, dk;
	private byte[] W0, W1, W2, W3;

	private static final int BLOCK_SIZE = 16;

	/**
	 * default constructor - 128 bit block size.
	 */
	public ARIAEngine() {
	}

	public String getAlgorithmName() {
		return "ARIA";
	}

	public int getBlockSize() {
		return BLOCK_SIZE;
	}

	/**
	 * initialise an ARIA cipher.
	 *
	 * @param forEncryption
	 *            whether or not we are for encryption.
	 * @param params
	 *            the parameters required to set up the cipher.
	 * @throws IllegalArgumentException
	 *             if the params argument is inappropriate.
	 */
	public void init(boolean forEncryption, CipherParameters params)
			throws IllegalArgumentException {

		if (params instanceof KeyParameter) {
			keyExpansion(((KeyParameter) params).getKey(), !forEncryption);
			return;
		}

		throw new IllegalArgumentException(
				"invalid parameter passed to ARIA init - "
						+ params.getClass().getName());
	}

	public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
			throws DataLengthException, IllegalStateException {

		if (ek == null && dk == null) {
			throw new IllegalStateException("ARIA engine not initialised");
		}

		if ((inOff + (32 / 2)) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + (32 / 2)) > out.length) {
			throw new DataLengthException("output buffer too short");
		}

		byte[] r;

		if (ek != null)
			r = encryptBlock(in, inOff);
		else
			r = decryptBlock(in, inOff);

		System.arraycopy(r, 0, out, outOff, r.length);

		return BLOCK_SIZE;
	}

	public void reset() {
		nRounds = 0;
		ek = null;
		dk = null;
		W0 = null;
		W1 = null;
		W2 = null;
		W3 = null;
	}

	private byte[] fo(byte[] in, byte[] ck) {
		byte[] out = new byte[16];
		for (int i = 0; i < 16; i++) {
			out[i] = (byte) (in[i] ^ ck[i]);
		}
		// SubstLayer
		for (int i = 0; i < 4; i++) {
			out[(i * 4)] = S1[(out[(i * 4)] >>> 4) & 0x0f][out[(i * 4)] & 0x0f];
			out[(i * 4) + 1] = S2[(out[((i * 4) + 1)] >>> 4) & 0x0f][out[((i * 4) + 1)] & 0x0f];
			out[(i * 4) + 2] = X1[(out[((i * 4) + 2)] >>> 4) & 0x0f][out[((i * 4) + 2)] & 0x0f];
			out[(i * 4) + 3] = X2[(out[((i * 4) + 3)] >>> 4) & 0x0f][out[((i * 4) + 3)] & 0x0f];
		}
		// DiffLayer
		return diff(out);
	}

	private byte[] fe(byte[] in, byte[] ck) {
		byte[] out = new byte[16];
		for (int i = 0; i < 16; i++) {
			out[i] = (byte) (in[i] ^ ck[i]);
		}
		// SubstLayer
		for (int i = 0; i < 4; i++) {
			out[(i * 4)] = X1[(out[(i * 4)] >>> 4) & 0x0f][out[(i * 4)] & 0x0f];
			out[(i * 4) + 1] = X2[(out[((i * 4) + 1)] >>> 4) & 0x0f][out[((i * 4) + 1)] & 0x0f];
			out[(i * 4) + 2] = S1[(out[((i * 4) + 2)] >>> 4) & 0x0f][out[((i * 4) + 2)] & 0x0f];
			out[(i * 4) + 3] = S2[(out[((i * 4) + 3)] >>> 4) & 0x0f][out[((i * 4) + 3)] & 0x0f];
		}
		// DiffLayer
		return diff(out);
	}

	private byte[] ff(byte[] in, byte[] ck, byte[] cck) {
		byte[] out = new byte[16];
		for (int i = 0; i < 16; i++) {
			out[i] = (byte) (in[i] ^ ck[i]);
		}
		// SubstLayer
		for (int i = 0; i < 4; i++) {
			out[(i * 4)] = X1[(out[(i * 4)] >>> 4) & 0x0f][out[(i * 4)] & 0x0f];
			out[(i * 4) + 1] = X2[(out[((i * 4) + 1)] >>> 4) & 0x0f][out[((i * 4) + 1)] & 0x0f];
			out[(i * 4) + 2] = S1[(out[((i * 4) + 2)] >>> 4) & 0x0f][out[((i * 4) + 2)] & 0x0f];
			out[(i * 4) + 3] = S2[(out[((i * 4) + 3)] >>> 4) & 0x0f][out[((i * 4) + 3)] & 0x0f];
		}
		for (int i = 0; i < 16; i++) {
			out[i] ^= cck[i];
		}
		return out;
	}

	private byte[] diff(byte[] in) {
		byte[] r = new byte[16];
		for (int i = 0; i < 16; i++) {
			switch (i) {
			case 0:
				r[i] = (byte) (in[3] ^ in[4] ^ in[6] ^ in[8] ^ in[9] ^ in[13] ^ in[14]);
				break;
			case 1:
				r[i] = (byte) (in[2] ^ in[5] ^ in[7] ^ in[8] ^ in[9] ^ in[12] ^ in[15]);
				break;
			case 2:
				r[i] = (byte) (in[1] ^ in[4] ^ in[6] ^ in[10] ^ in[11] ^ in[12] ^ in[15]);
				break;
			case 3:
				r[i] = (byte) (in[0] ^ in[5] ^ in[7] ^ in[10] ^ in[11] ^ in[13] ^ in[14]);
				break;
			case 4:
				r[i] = (byte) (in[0] ^ in[2] ^ in[5] ^ in[8] ^ in[11] ^ in[14] ^ in[15]);
				break;
			case 5:
				r[i] = (byte) (in[1] ^ in[3] ^ in[4] ^ in[9] ^ in[10] ^ in[14] ^ in[15]);
				break;
			case 6:
				r[i] = (byte) (in[0] ^ in[2] ^ in[7] ^ in[9] ^ in[10] ^ in[12] ^ in[13]);
				break;
			case 7:
				r[i] = (byte) (in[1] ^ in[3] ^ in[6] ^ in[8] ^ in[11] ^ in[12] ^ in[13]);
				break;
			case 8:
				r[i] = (byte) (in[0] ^ in[1] ^ in[4] ^ in[7] ^ in[10] ^ in[13] ^ in[15]);
				break;
			case 9:
				r[i] = (byte) (in[0] ^ in[1] ^ in[5] ^ in[6] ^ in[11] ^ in[12] ^ in[14]);
				break;
			case 10:
				r[i] = (byte) (in[2] ^ in[3] ^ in[5] ^ in[6] ^ in[8] ^ in[13] ^ in[15]);
				break;
			case 11:
				r[i] = (byte) (in[2] ^ in[3] ^ in[4] ^ in[7] ^ in[9] ^ in[12] ^ in[14]);
				break;
			case 12:
				r[i] = (byte) (in[1] ^ in[2] ^ in[6] ^ in[7] ^ in[9] ^ in[11] ^ in[12]);
				break;
			case 13:
				r[i] = (byte) (in[0] ^ in[3] ^ in[6] ^ in[7] ^ in[8] ^ in[10] ^ in[13]);
				break;
			case 14:
				r[i] = (byte) (in[0] ^ in[3] ^ in[4] ^ in[5] ^ in[9] ^ in[11] ^ in[14]);
				break;
			case 15:
				r[i] = (byte) (in[1] ^ in[2] ^ in[4] ^ in[5] ^ in[8] ^ in[10] ^ in[15]);
				break;
			}
		}
		return r;
	}

	private void keyExpansion(byte[] key, boolean forDecryption) {
		byte[] KL = new byte[16];
		byte[] KR = new byte[16];

		W0 = new byte[16];
		W1 = new byte[16];
		W2 = new byte[16];
		W3 = new byte[16];

		/*
		 * key length CK1 CK2 CK3 128 C0 C1 C2 192 C1 C2 C3 256 C2 C0 C1
		 */
		int n;
		switch (key.length) {
		case 16:
			n = 0;
			nRounds = 12;
			break;
		case 24:
			n = 1;
			nRounds = 14;
			break;
		case 32:
			n = 2;
			nRounds = 16;
			break;
		default:
			throw new InternalError(
					"expected argument length is 16, 24, and 32. but, "
							+ key.length);
		}

		byte[] CK1 = C[n];
		byte[] CK2 = C[(n + 1) % C.length];
		byte[] CK3 = C[(n + 2) % C.length];

		// KL = key[0..15];
		System.arraycopy(key, 0, KL, 0, 16);
		// KR = key[16..31];
		System.arraycopy(key, 16, KR, 0, (key.length - 16));

		// W[0] = KL;
		System.arraycopy(KL, 0, W0, 0, 16);
		// W[1] = Fo[W[0], CK1) XOR KR
		W1 = XOR(fo(W0, CK1), KR);
		// W[2] = Fe(W[1], CK2) XOR W[0]
		W2 = XOR(fe(W1, CK2), W0);
		// W[3] = Fo(W[2], CK3) XOR W[1]
		W3 = XOR(fo(W2, CK3), W1);

		generateRoundKeys(forDecryption);
	}

	private void generateRoundKeys(boolean forDecryption) {
		int n = nRounds + 1;
		// round key generation part
		ek = new byte[n][16];

		ek[0] = XOR(W0, circularRightShift(W1, 19));
		ek[1] = XOR(W1, circularRightShift(W2, 19));
		ek[2] = XOR(W2, circularRightShift(W3, 19));
		ek[3] = XOR(circularRightShift(W0, 19), W3);
		ek[4] = XOR(W0, circularRightShift(W1, 31));
		ek[5] = XOR(W1, circularRightShift(W2, 31));
		ek[6] = XOR(W2, circularRightShift(W3, 31));
		ek[7] = XOR(circularRightShift(W0, 31), W3);
		ek[8] = XOR(W0, circularLeftShift(W1, 61));
		ek[9] = XOR(W1, circularLeftShift(W2, 61));
		ek[10] = XOR(W2, circularLeftShift(W3, 61));
		ek[11] = XOR(circularLeftShift(W0, 61), W3);
		ek[12] = XOR(W0, circularLeftShift(W1, 31));
		if (nRounds > 12) {
			ek[13] = XOR(W1, circularLeftShift(W2, 31));
			ek[14] = XOR(W2, circularLeftShift(W3, 31));
		}
		if (nRounds > 14) {
			ek[15] = XOR(circularLeftShift(W0, 31), W3);
			ek[16] = XOR(W0, circularLeftShift(W1, 19));
		}

		if (forDecryption) {
			dk = new byte[n][16];
			for (int i = 0; i < n; i++) {
				dk[i] = (i == 0 || i == (n - 1)) ? ek[n - i - 1] : diff(ek[n
						- i - 1]);
			}
			ek = null;
		}
	}

	private byte[] XOR(byte[] b1, byte[] b2) {
		byte[] b = new byte[b1.length];
		for (int i = 0, len = b.length; i < len; i++) {
			b[i] = (byte) (b1[i] ^ b2[i]);
		}
		return b;
	}

	private byte[] circularLeftShift(byte[] b, int n) {
		int[] ia = toIntArray(b);
		int temp;

		for (int i = 0, len = (n >> 5); i < len; i++) {
			temp = ia[0];
			ia[0] = ia[1];
			ia[1] = ia[2];
			ia[2] = ia[3];
			ia[3] = temp;
		}

		int nShift = n % 32;
		int shift = getLeftShiftBit(nShift);

		temp = (ia[0] & shift) >>> (32 - nShift);
		ia[0] <<= nShift;
		ia[0] |= (ia[1] & shift) >>> (32 - nShift);
		ia[1] <<= nShift;
		ia[1] |= (ia[2] & shift) >>> (32 - nShift);
		ia[2] <<= nShift;
		ia[2] |= (ia[3] & shift) >>> (32 - nShift);
		ia[3] <<= nShift;
		ia[3] |= temp;

		return toByteArray(ia);
	}

	private int getLeftShiftBit(int shift) {
		int s = 0x80000000;
		int r = 0;
		for (int i = 0; i < shift; i++, s >>= 1)
			r |= s;
		return r;
	}

	private byte[] circularRightShift(byte[] b, int n) {
		int[] ia = toIntArray(b);
		int temp;

		for (int i = 0, len = (n / 32); i < len; i++) {
			temp = ia[3];
			ia[3] = ia[2];
			ia[2] = ia[1];
			ia[1] = ia[0];
			ia[0] = temp;
		}

		int nShift = n % 32;
		int shift = getRightShiftBit(nShift);

		temp = (ia[3] & shift);
		ia[3] >>>= nShift;
		ia[3] |= ((ia[2] & shift) << (32 - nShift));
		ia[2] >>>= nShift;
		ia[2] |= ((ia[1] & shift) << (32 - nShift));
		ia[1] >>>= nShift;
		ia[1] |= ((ia[0] & shift) << (32 - nShift));
		ia[0] >>>= nShift;
		ia[0] |= (temp << (32 - nShift));

		return toByteArray(ia);
	}

	private int getRightShiftBit(int shift) {
		int s = 0x00000001;
		int r = 0;
		for (int i = 0; i < shift; i++, s <<= 1)
			r |= s;
		return r;
	}

	private int[] toIntArray(byte[] b) {
		if (b.length != 16)
			throw new InternalError("expected argument length is 16. but, "
					+ b.length);
		int[] r = new int[4];
		for (int i = 0; i < 4; i++) {
			r[i] = (b[(i * 4)] & 0x000000ff) << 24
					| (b[(i * 4) + 1] & 0x000000ff) << 16
					| (b[(i * 4) + 2] & 0x000000ff) << 8
					| (b[(i * 4) + 3] & 0x000000ff);
		}
		return r;
	}

	private byte[] toByteArray(int[] ia) {
		if (ia.length != 4)
			throw new InternalError("expected argument length is 4. but, "
					+ ia.length);
		byte[] b = new byte[16];
		for (int i = 0; i < 4; i++) {
			b[(i * 4)] = (byte) ((ia[i] >>> 24) & 0xff);
			b[(i * 4) + 1] = (byte) ((ia[i] >>> 16) & 0xff);
			b[(i * 4) + 2] = (byte) ((ia[i] >>> 8) & 0xff);
			b[(i * 4) + 3] = (byte) (ia[i] & 0xff);
		}
		return b;
	}

	private byte[] encryptBlock(byte[] b, int off) {
		byte[] r = new byte[BLOCK_SIZE];
		System.arraycopy(b, off, r, 0, BLOCK_SIZE);

		int i;
		for (i = 0; i < nRounds - 1; i++) {
			if ((i % 2) == 0)
				r = fo(r, ek[i]);
			else
				r = fe(r, ek[i]);
		}

		return ff(r, ek[i], ek[i + 1]);
	}

	private byte[] decryptBlock(byte[] b, int off) {
		byte[] r = new byte[BLOCK_SIZE];
		System.arraycopy(b, off, r, 0, BLOCK_SIZE);

		int i;
		for (i = 0; i < nRounds - 1; i++) {
			if (i % 2 == 0)
				r = fo(r, dk[i]);
			else
				r = fe(r, dk[i]);
		}

		return ff(r, dk[i], dk[i + 1]);
	}

}
