package com.jiter.app.config

import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import java.util.Locale

enum class AppLanguage(val languageTag: String) {
    SYSTEM(""),
    INDONESIAN("id"),
    ENGLISH("en"),
}

/**
 * Runtime app-language switcher supporting Bahasa Indonesia (id/in), English (en),
 * and System Default via AndroidX AppCompat per-app locales.
 * Switching language recreates only the UI Activity and NEVER interrupts the VPN tunnel.
 */
object LanguageManager {

    fun currentSelection(): AppLanguage {
        val locales = AppCompatDelegate.getApplicationLocales()
        if (locales.isEmpty) return AppLanguage.SYSTEM
        val first = locales[0] ?: return AppLanguage.SYSTEM
        return fromLanguageCode(first.language)
    }

    fun apply(language: AppLanguage) {
        val locales = if (language == AppLanguage.SYSTEM) {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(language.languageTag)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }

    fun toggleIndonesianEnglish(
        current: AppLanguage = currentSelection(),
        systemLanguageCode: String = Locale.getDefault().language,
    ): AppLanguage {
        val effectiveIsIndonesian = when (current) {
            AppLanguage.INDONESIAN -> true
            AppLanguage.ENGLISH -> false
            AppLanguage.SYSTEM -> isIndonesianCode(systemLanguageCode)
        }
        return if (effectiveIsIndonesian) AppLanguage.ENGLISH else AppLanguage.INDONESIAN
    }

    fun fromLanguageCode(code: String?): AppLanguage = when {
        code.isNullOrBlank() -> AppLanguage.SYSTEM
        isIndonesianCode(code) -> AppLanguage.INDONESIAN
        code.lowercase(Locale.ROOT).startsWith("en") -> AppLanguage.ENGLISH
        else -> AppLanguage.SYSTEM
    }

    fun isIndonesianCode(code: String?): Boolean {
        val norm = code?.lowercase(Locale.ROOT) ?: return false
        return norm == "id" || norm == "in" || norm.startsWith("id-") || norm.startsWith("in-")
    }
}
