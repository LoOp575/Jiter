package com.jiter.app.state

import com.jiter.app.engine.SessionSnapshot
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Stateless RAM-only session state store.
 * No persistent database or usage history is ever written to disk.
 * Cleared immediately on STOP.
 */
object SessionStore {
    private val _snapshot = MutableStateFlow(SessionSnapshot())
    val snapshot: StateFlow<SessionSnapshot> = _snapshot.asStateFlow()

    fun update(transform: (SessionSnapshot) -> SessionSnapshot) {
        _snapshot.update(transform)
    }

    fun clear() {
        _snapshot.value = SessionSnapshot()
    }
}
