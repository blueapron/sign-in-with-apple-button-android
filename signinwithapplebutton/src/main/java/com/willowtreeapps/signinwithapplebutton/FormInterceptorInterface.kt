package com.willowtreeapps.signinwithapplebutton

import android.webkit.JavascriptInterface
import java.io.IOException

/**
 * [JavascriptInterface] to be injected in a WebView (with name [NAME], see [WebView.addJavascriptInterface]) that
 * receives the "form_data" from a web page (triggered by [JS_TO_INJECT]) and analyzes the 2 expected fields from apple
 * authentication:
 * - [STATE] : a _nonce_ string set in [AuthenticationAttempt.create] that needs to match [expectedState];
 * - [CODE] : the authorization code that'll be used to authenticate the user.
 */
class FormInterceptorInterface(
    private val expectedState: String,
    private val callback: ((SignInWithAppleResult) -> Unit)?,
    private val cancel: (() -> Unit)?
) {
    @JavascriptInterface
    fun processFormData(formData: String) {
        val values = formData.split(FORM_DATA_SEPARATOR)
        val codeEncoded = values.find { it.startsWith(CODE_KEY) }
        val stateEncoded = values.find { it.startsWith(STATE_KEY) }
        val idTokenEncoded = values.find { it.startsWith(ID_TOKEN_KEY) }
        val errorEncoded = values.find { it.startsWith(ERROR_KEY) }

        if (errorEncoded != null) {
            val errorValue = errorEncoded.substringAfter(KEY_VALUE_SEPARATOR);
            callback?.invoke (
                if (errorValue == CANCELLED_VALUE)
                    SignInWithAppleResult.Cancel
                else
                    SignInWithAppleResult.Failure(IOException("Apple Error: $errorValue"))
            )
            cancel?.invoke()
            return
        }

        if (codeEncoded == null || stateEncoded == null || idTokenEncoded == null) {
            callback?.invoke(SignInWithAppleResult.Failure(IOException("The response did not contain one or any of state, code, or token")))
            return
        }

        val stateValue = stateEncoded.substringAfter(KEY_VALUE_SEPARATOR)
        val codeValue = codeEncoded.substringAfter(KEY_VALUE_SEPARATOR)
        val idTokenValue = idTokenEncoded.substringAfter(KEY_VALUE_SEPARATOR)

        callback?.invoke(
            if (stateValue == expectedState)
                SignInWithAppleResult.Success(codeValue, idTokenValue)
            else
                SignInWithAppleResult.Failure(IOException("The response's state does not match the expected state."))
        )
    }

    companion object {
        const val NAME = "FormInterceptorInterface"
        private const val STATE_KEY = "state"
        private const val CODE_KEY = "code"
        private const val ID_TOKEN_KEY = "id_token"
        private const val ERROR_KEY = "error"
        private const val CANCELLED_VALUE = "user_cancelled_authorize"
        private const val FORM_DATA_SEPARATOR = "|"
        private const val KEY_VALUE_SEPARATOR = "="

        /**
         * This piece of Javascript code fetches all (key, value) attributes from the site's form data and concatenates
         * them in the form: "key [KEY_VALUE_SEPARATOR] value [FORM_DATA_SEPARATOR]".
         * Then, invokes the method [processFormData] on the app's side (that's exposed to Javascript) so that the form
         * data can be analyzed in the app's context.
         */
        val JS_TO_INJECT = """
        function parseForm(form){
            var values = '';
            for(var i=0 ; i< form.elements.length; i++){
                values +=
                    form.elements[i].name +
                    '${KEY_VALUE_SEPARATOR}' +
                    form.elements[i].value +
                    '${FORM_DATA_SEPARATOR}'
            }
            $NAME.processFormData(values);
        }

        for(var i=0 ; i< document.forms.length ; i++){
            parseForm(document.forms[i]);
        }
        """.trimIndent()
    }
}