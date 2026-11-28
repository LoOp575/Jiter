package com.jiter.app.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.CornerPathEffect
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import androidx.core.content.ContextCompat
import com.jiter.app.R
import kotlin.math.max
import kotlin.math.min

/**
 * Live 60-second RTT sparkline with smooth rounded path transitions, soft cyan glow,
 * and a glowing endpoint marker matching the JITER minimalist dashboard redesign.
 */
class LatencySparklineView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    private val dp = resources.displayMetrics.density

    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 5.5f * dp
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        pathEffect = CornerPathEffect(10f * dp)
        color = Color.argb(45, 34, 211, 238)
    }

    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2.2f * dp
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
        pathEffect = CornerPathEffect(10f * dp)
        color = ContextCompat.getColor(context, R.color.jiter_cyan)
    }

    private val dotHaloPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = Color.argb(65, 34, 211, 238)
    }

    private val dotPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
        color = ContextCompat.getColor(context, R.color.jiter_cyan)
    }

    private val path = Path()
    private var samples: List<Double> = emptyList()

    fun setSeries(values: List<Double>, accentColor: Int) {
        samples = values
        linePaint.color = accentColor
        dotPaint.color = accentColor
        val r = Color.red(accentColor)
        val g = Color.green(accentColor)
        val b = Color.blue(accentColor)
        glowPaint.color = Color.argb(46, r, g, b)
        dotHaloPaint.color = Color.argb(72, r, g, b)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 16f * dp || h <= 12f * dp) return

        val padLeft = 4f * dp
        val padRight = 8f * dp
        val padTop = 8f * dp
        val padBottom = 8f * dp
        val drawW = w - padLeft - padRight
        val drawH = h - padTop - padBottom
        val midY = padTop + drawH * 0.5f

        path.reset()

        if (samples.isEmpty()) {
            // Calm flat standby baseline
            path.moveTo(padLeft, midY)
            path.lineTo(padLeft + drawW, midY)
            canvas.drawPath(path, glowPaint)
            canvas.drawPath(path, linePaint)
            canvas.drawCircle(padLeft + drawW, midY, 7f * dp, dotHaloPaint)
            canvas.drawCircle(padLeft + drawW, midY, 3.8f * dp, dotPaint)
            return
        }

        val pts = if (samples.size == 1) listOf(samples[0], samples[0]) else samples

        var minVal = Double.MAX_VALUE
        var maxVal = Double.MIN_VALUE
        for (v in pts) {
            minVal = min(minVal, v)
            maxVal = max(maxVal, v)
        }
        // Keep calm variance visually gentle (at least a 40 ms vertical window so 35..38 ms stays smooth)
        val center = (minVal + maxVal) * 0.5
        val span = max(40.0, (maxVal - minVal) * 1.45)
        val low = center - span * 0.5
        val high = center + span * 0.5

        val stepX = drawW / max(1, pts.size - 1)
        var lastX = padLeft
        var lastY = midY

        pts.forEachIndexed { idx, value ->
            val x = padLeft + idx * stepX
            val norm = ((value - low) / (high - low)).coerceIn(0.0, 1.0)
            // Higher RTT rises upward slightly like a live telemetry oscilloscope
            val y = padTop + drawH * (1f - norm.toFloat())
            if (idx == 0) {
                path.moveTo(x, y)
            } else {
                path.lineTo(x, y)
            }
            lastX = x
            lastY = y
        }

        canvas.drawPath(path, glowPaint)
        canvas.drawPath(path, linePaint)
        canvas.drawCircle(lastX, lastY, 8f * dp, dotHaloPaint)
        canvas.drawCircle(lastX, lastY, 4.2f * dp, dotPaint)
    }
}
