package de.jmens.google.authenticator;

import static java.text.MessageFormat.format;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.Paths;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

public class QrCodeGenerator {

	public static Optional<byte[]> generateQRCodePng(String secret, String application, int size) {

		try (final ByteArrayOutputStream output = new ByteArrayOutputStream()) {

			final String text = URLEncoder.encode(format("otpauth://totp/{0}?secret={1}", application, secret), "UTF-8");

			final Map<EncodeHintType, Object> hintMap = new EnumMap<>(EncodeHintType.class);
			hintMap.put(EncodeHintType.CHARACTER_SET, "UTF-8");
			hintMap.put(EncodeHintType.MARGIN, 1);
			hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H);

			final QRCodeWriter qrCodeWriter = new QRCodeWriter();
			final BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, size, size, hintMap);

			MatrixToImageWriter.writeToStream(bitMatrix, "PNG", output);
			MatrixToImageWriter.writeToPath(bitMatrix, "PNG", Paths.get("/tmp/foo.png"));

			return Optional.ofNullable(output.toByteArray());

		} catch (WriterException | IOException e) {
			return Optional.empty();
		}
	}
}
