async function analyzeLog(event) {
    event.preventDefault()
    const log = document.getElementById('logInput').value

    if (!log) {
        alert('Please paste a network log first!')
        return
    }

    document.getElementById('loading').style.display = 'block'
    document.getElementById('result').style.display = 'none'
    document.getElementById('severity').style.display = 'none'

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log: log })
        })

        const data = await response.json()

        if (!data.success) {
            document.getElementById('result').style.display = 'block'
            document.getElementById('result').innerText = `❌ ${data.error}`
            return
        }

        document.getElementById('severity').style.display = 'block'
        document.getElementById('severity').innerText =
            `${data.severity.color} THREAT SCORE: ${data.severity.score}/10 — ${data.severity.level}`

        document.getElementById('result').style.display = 'block'
        document.getElementById('result').innerText = data.analysis

    } catch (error) {
        document.getElementById('result').style.display = 'block'
        document.getElementById('result').innerText = '❌ Error connecting to server.'
    }

    document.getElementById('loading').style.display = 'none'
}

async function resetMemory() {
    const response = await fetch('/api/reset', { method: 'POST' })
    const data = await response.json()
    if (data.success) {
        alert(data.message)
    }
}