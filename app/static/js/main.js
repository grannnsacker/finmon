async function searchAsset() {
    const symbol = document.getElementById('symbol').value;
    const assetType = document.getElementById('assetType').value;
    const resultDiv = document.getElementById('result');
    const chartDiv = document.getElementById('chart');

    console.log('Searching for:', symbol, 'Type:', assetType); // Debug log

    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/search/${symbol}?asset_type=${assetType}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        const data = await response.json();

        console.log('API Response:', data); // Debug log

        if (response.ok) {
            resultDiv.style.display = 'block';
            const priceValue = parseFloat(data['price']); // или quote['05. price']
            document.querySelector('.asset-name').textContent = `${symbol} Stock`;
            document.querySelector('.price').textContent =  `Price: $${priceValue.toFixed(2)}`;
        } else {
            throw new Error(data.detail || 'Failed to fetch asset data');
        }
    } catch (error) {
        console.error('Search Error:', error);
        alert('Error searching for asset');
        resultDiv.style.display = 'none';
        chartDiv.style.display = 'none';
    }
}

async function addToFavorites() {
    const symbol = document.getElementById('symbol').value;
    const assetType = document.getElementById('assetType').value;

    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/favorites/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                symbol: symbol,
                asset_type: assetType
            })
        });
        if (response.status === 401 || response.status === 403) {
            window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
            return;
        }
        console.log('Response status:', response.status, typeof response.status, response.status === 409);
        if (response.status === 409) {
                alert('Этот актив уже добавлен в избранные.');
                return;
         } else {
            if (response.ok) {
                alert('Успешо добавлено в избранные!');
            } else {
                throw new Error('Failed to add to favorites');
            }
        }
    } catch (error) {
        alert('Ошибка добавления');
    }
}

async function removeFavorite(favoriteId) {
    if (!confirm('Вы уверены что хотите удалить?')) {
        return;
    }

    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/favorites/${favoriteId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            window.location.reload();
        } else {
            throw new Error('Failed to remove favorite');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error removing favorite. Please try again.');
    }
}

async function showChart(symbol, assetType) {
    try {
        const token = localStorage.getItem('token');
        let endpoint = assetType === 'stock'
            ? `https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=${symbol}&apikey=${ALPHA_VANTAGE_API_KEY}`
            : `https://rest.coinapi.io/v1/ohlcv/${symbol}/USD/history?period_id=1DAY&limit=100`;

        const headers = assetType === 'crypto'
            ? { 'X-CoinAPI-Key': COINAPI_KEY }
            : {};

        const response = await fetch(endpoint, { headers });
        const data = await response.json();

        let dates = [];
        let prices = [];

        if (assetType === 'stock') {
            const timeSeries = data['Time Series (Daily)'];
            for (let date in timeSeries) {
                dates.push(date);
                prices.push(parseFloat(timeSeries[date]['4. close']));
            }
        } else {
            data.forEach(item => {
                dates.push(item.time_period_start.split('T')[0]);
                prices.push(item.price_close);
            });
        }

        const trace = {
            x: dates,
            y: prices,
            type: 'scatter',
            mode: 'lines',
            name: symbol,
            line: {
                color: '#007bff',
                width: 2
            }
        };

        const layout = {
            title: `${symbol} Price History`,
            xaxis: {
                title: 'Date',
                showgrid: false
            },
            yaxis: {
                title: 'Price (USD)',
                showgrid: true
            },
            paper_bgcolor: 'rgba(0,0,0,0)',
            plot_bgcolor: 'rgba(0,0,0,0)',
            margin: { t: 30 }
        };

        Plotly.newPlot('chart', [trace], layout);
    } catch (error) {
        console.error('Error:', error);
        alert('Error loading chart data. Please try again.');
    }
}

async function fetchWithAuth(url, options = {}) {
    const token = localStorage.getItem('token');
    console.log('Token from storage:', token); // Debug log
    
    if (!options.headers) {
        options.headers = {};
    }
    
    if (token) {
        options.headers['Authorization'] = `Bearer ${token}`;
        console.log('Setting Authorization header:', options.headers['Authorization']); // Debug log
    } else {
        console.log('No token found in storage'); // Debug log
        window.location.href = '/login';
        return null;
    }
    
    try {
        console.log('Sending request to:', url, 'with options:', options); // Debug log
        const response = await fetch(url, options);
        console.log('Response status:', response.status); // Debug log
        
        if (response.status === 401 || response.status === 403) {
            console.log('Unauthorized response'); // Debug log
            localStorage.removeItem('token');
            window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
            return null;
        }
        
        return response;
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}

async function showFavoriteChart(symbol, assetType, favId) {
    const chartDiv = document.getElementById(`chart-${favId}`);
    chartDiv.style.display = 'block';
    chartDiv.innerHTML = 'Loading...';
    try {
        const resp = await fetch(`/history/${symbol}?asset_type=${assetType}`);
        const data = await resp.json();
        if (resp.ok && data.length > 0) {
            const dates = data.map(d => d.date);
            const closes = data.map(d => d.close);
            Plotly.newPlot(chartDiv, [{
                x: dates,
                y: closes,
                type: 'scatter',
                mode: 'lines+markers',
                line: {color: 'green'}
            }], {
                title: `${symbol} Price (Last 30 Days)`,
                xaxis: {title: 'Date'},
                yaxis: {title: 'Close Price'}
            });
        } else {
            chartDiv.innerHTML = 'No data available';
        }
    } catch (e) {
        chartDiv.innerHTML = 'Error loading chart';
    }
}
