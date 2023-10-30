package oauth.kakao.util;

import oauth.kakao.dto.common.ExceptionResponseBody;
import oauth.kakao.dto.common.SuccessResponseBody;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

import java.util.List;
import java.util.stream.Collectors;

public interface DefaultHttpResponse {
    ResponseEntity<SuccessResponseBody> OK_WITH_NO_DATA = ResponseEntity.ok(new SuccessResponseBody(
            String.valueOf(HttpStatus.OK.value()),
            DefaultHttpMessage.OK,
            null));

    static ResponseEntity<SuccessResponseBody> DEFAULT_SUCCESS_RESPONSE(Object data) {
        return ResponseEntity.ok(new SuccessResponseBody(
                String.valueOf(HttpStatus.OK.value()),
                DefaultHttpMessage.OK,
                data));
    }

    static ResponseEntity<ExceptionResponseBody> DEFAULT_BINDING_ERROR_RESPONSE(BindingResult bindingResult) {

        List<String> errorList = bindingResult.getFieldErrors()
                .stream().map(fieldError -> fieldError.getField() + ":" + fieldError.getDefaultMessage())
                .collect(Collectors.toList());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST.value()).body(
                new ExceptionResponseBody(
                        String.valueOf(HttpStatus.BAD_REQUEST.value()), errorList, null));
    }

    static ResponseEntity<ExceptionResponseBody> DEFAULT_ERROR_RESPONSE(String message) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST.value()).body(
                new ExceptionResponseBody(String.valueOf(HttpStatus.BAD_REQUEST.value()),
                        message,
                        null));
    }

}
