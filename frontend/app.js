const form = document.getElementById('form');
const estado = document.getElementById('estado');
const resultado = document.getElementById('resultado');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('url').value.trim();
  estado.classList.remove('oculto');
  resultado.classList.add('oculto');
  try {
    const r = await fetch('/analizar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await r.json();
    estado.classList.add('oculto');
    if (!r.ok) {
      alert(data.detail || data.error || 'Error analizando la URL');
      return;
    }

    const v = document.getElementById('veredicto');
    const barra = document.querySelector('.barra');
    const riesgoTxt = document.getElementById('riesgoTxt');
    const explicacion = document.getElementById('explicacion');

    if (!data.veredicto) {
      // URL no evaluable: sin veredicto, estilo neutro
      v.textContent = 'NO EVALUABLE';
      v.className = 'noEvaluable';
      barra.classList.add('oculto');
      riesgoTxt.textContent = '';
      explicacion.textContent = data.explicacion;
    } else {
      v.textContent = data.veredicto.toUpperCase();
      v.className = data.veredicto;
      barra.classList.remove('oculto');
      document.getElementById('nivel').style.width = data.riesgo + '%';
      riesgoTxt.textContent = `Nivel de riesgo: ${data.riesgo}/100`;
      explicacion.textContent = data.explicacion;
    }

    document.getElementById('detalle').textContent = JSON.stringify(data.detalle_modulos, null, 2);
    resultado.classList.remove('oculto');
  } catch (err) {
    estado.classList.add('oculto');
    alert('Error de red: ' + err.message);
  }
});
