package com.jiter.app.ui

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import com.jiter.app.R
import kotlin.math.min

/**
 * Circular animated latency gauge ring matching JITER's dark minimalist home design.
 * Draws a clean midnight track with a smooth rounded-cap glowing arc starting at 12 o'clock.
 */
class LatencyRingView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    private val dp = resources.displayMetrics.density
    private val strokePx = 9f * dp
    private val glowStrokePx = 16f * dp

    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = strokePx
        strokeCap = Paint.Cap.ROUND
        color = ContextCompat.getColor(context, R.color.jiter_ring_track)
    }

    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = glowStrokePx
        strokeCap = Paint.Cap.ROUND
        color = Color.argb(38, 34, 211, 238)
    }

    private val arcPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = strokePx
        strokeCap = Paint.Cap.ROUND
        color = ContextCompat.getColor(context, R.color.jiter_cyan)
    }

    private val arcBounds = RectF()

    private var currentSweepDeg: Float = 82f
    private var targetSweepDeg: Float = 82f
    private var startAngleDeg: Float = -90f
    private var isConnecting: Boolean = false

    private var sweepAnimator: ValueAnimator? = null
    private var spinAnimator: ValueAnimator? = null

    fun setRingState(
        progressFraction: Float,
        accentColor: Int,
        connecting: Boolean,
    ) {
        val clamped = progressFraction.coerceIn(0.08f, 0.94f)
        arcPaint.color = accentColor
        glowPaint.color = Color.argb(
            42,
            Color.red(accentColor),
            Color.green(accentColor),
            Color.blue(accentColor),
        )

        val newTarget = clamped * 360f
        if (kotlin.math.abs(newTarget - targetSweepDeg) > 1.5f) {
            targetSweepDeg = newTarget
            sweepAnimator?.cancel()
            sweepAnimator = ValueAnimator.ofFloat(currentSweepDeg, targetSweepDeg).apply {
                duration = 380L
                interpolator = DecelerateInterpolator()
                addUpdateListener { anim ->
                    currentSweepDeg = anim.animatedValue as Float
                    invalidate()
                }
                start()
            }
        }

        if (connecting != isConnecting) {
            isConnecting = connecting
            if (connecting) {
                startSpin()
            } else {
                stopSpin()
            }
        }
        invalidate()
    }

    private fun startSpin() {
        spinAnimator?.cancel()
        spinAnimator = ValueAnimator.ofFloat(-90f, 270f).apply {
            duration = 1_400L
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener { anim ->
                startAngleDeg = anim.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    private fun stopSpin() {
        spinAnimator?.cancel()
        spinAnimator = null
        startAngleDeg = -90f
        invalidate()
    }

    override fun onDetachedFromWindow() {
        sweepAnimator?.cancel()
        spinAnimator?.cancel()
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val size = min(width, height).toFloat()
        if (size <= glowStrokePx) return

        val inset = glowStrokePx * 0.65f
        val left = (width - size) * 0.5f + inset
        val top = (height - size) * 0.5f + inset
        arcBounds.set(left, top, left + size - inset * 2f, top + size - inset * 2f)

        canvas.drawOval(arcBounds, trackPaint)
        canvas.drawArc(arcBounds, startAngleDeg, currentSweepDeg, false, glowPaint)
        canvas.drawArc(arcBounds, startAngleDeg, currentSweepDeg, false, arcPaint)
    }
}
