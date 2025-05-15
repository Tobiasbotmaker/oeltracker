document.addEventListener('DOMContentLoaded', function () {
    // Apply the saved theme globally
    const savedTheme = localStorage.getItem('theme') || 'classic';
    document.body.className = savedTheme + '-theme';

    // Cookie banner logic
    const cookiePopup = document.getElementById('cookie-popup');
    const acceptAllButton = document.getElementById('accept-all-cookies');
    const acceptSelectedButton = document.getElementById('accept-selected-cookies');
    const declineAllButton = document.getElementById('decline-all-cookies');
    const performanceCheckbox = document.getElementById('performance-cookies');
    const necessaryInfoBtn = document.getElementById('necessary-info-btn');
    const performanceInfoBtn = document.getElementById('performance-info-btn');
    const necessaryInfo = document.getElementById('necessary-info');
    const performanceInfo = document.getElementById('performance-info');

    // Check if cookies have already been accepted or declined
    if (!localStorage.getItem('cookiesAccepted')) {
        cookiePopup.style.display = 'block'; // Show the popup
    }

    // Handle "Accept All" button click
    acceptAllButton.addEventListener('click', function () {
        localStorage.setItem('cookiesAccepted', 'all');
        document.cookie = "cookie_consent=all; path=/; max-age=31536000"; // 1 år
        cookiePopup.style.display = 'none'; // Hide the popup
    });

    // Handle "Accept Selected" button click
    acceptSelectedButton.addEventListener('click', function () {
        const selectedCookies = {
            performance: performanceCheckbox.checked,
        };
        localStorage.setItem('cookiesAccepted', JSON.stringify(selectedCookies));
        document.cookie = `cookie_consent=${JSON.stringify(selectedCookies)}; path=/; max-age=31536000`; // 1 år
        cookiePopup.style.display = 'none'; // Hide the popup
    });

    // Handle "Decline All" button click
    declineAllButton.addEventListener('click', function () {
        localStorage.setItem('cookiesAccepted', 'none');
        document.cookie = "cookie_consent=none; path=/; max-age=31536000"; // 1 år
        cookiePopup.style.display = 'none'; // Hide the popup
    });

    // Toggle necessary cookies info
    necessaryInfoBtn.addEventListener('click', function () {
        necessaryInfo.classList.toggle('hidden'); // Brug kun classList.toggle
    });

    // Toggle performance cookies info
    performanceInfoBtn.addEventListener('click', function () {
        performanceInfo.classList.toggle('hidden'); // Brug kun classList.toggle
    });

    // Tilføj event listener til registreringsknappen
    const registerButton = document.querySelector('button[onclick="requestLocation()"]');
    if (registerButton) {
        registerButton.addEventListener('click', requestLocation);
    }

    // Handle email link click
    const emailLink = document.getElementById('email-link');
    if (emailLink) {
        emailLink.addEventListener('click', function () {
            navigator.clipboard.writeText('ØlSpillet@gmail.com')
                .then(function () {
                    alert('E-mail kopieret til udklipsholderen!');
                })
                .catch(function (err) {
                    console.error('Kunne ikke kopiere e-mailen: ', err);
                });
        });
    }

    // Theme selection logic (only on settings.html)
    const themeSelect = document.getElementById('themeSelect');
    if (themeSelect) {
        themeSelect.addEventListener('change', function () {
            const theme = themeSelect.value;
            localStorage.setItem('theme', theme);
            document.body.className = theme + '-theme';
        });

        // Set the dropdown to the saved theme
        themeSelect.value = savedTheme;
    }

    // Event handlers for "Registrer øl" and "Slet øl" buttons
    const addBeerButton = document.getElementById('addBeerButton');
    const deleteBeerButton = document.getElementById('deleteBeerButton');

    if (addBeerButton) {
        addBeerButton.addEventListener('click', function () {
            document.getElementById('addBeerForm').submit();
        });
    }

    if (deleteBeerButton) {
        deleteBeerButton.addEventListener('click', function () {
            const confirmResult = confirm("Er du sikker på, at du vil slette en øl?");
            if (confirmResult) {
                document.getElementById('deleteBeerForm').submit();
            }
        });
    }

    // Find tekstfeltet og tælleren
    const bioTextarea = document.getElementById('bio');
    const bioCounter = document.getElementById('bio-counter');

    // Tjek, om elementerne findes, før du tilføjer event listeners
    if (bioTextarea && bioCounter) {
        // Opdater tælleren, når brugeren skriver
        bioTextarea.addEventListener('input', function () {
            const currentLength = bioTextarea.value.length;
            const maxLength = bioTextarea.getAttribute('maxlength');
            bioCounter.textContent = `${currentLength}/${maxLength}`;
        });

        // Initial opdatering af tælleren
        const initialLength = bioTextarea.value.length;
        const maxLength = bioTextarea.getAttribute('maxlength');
        bioCounter.textContent = `${initialLength}/${maxLength}`;
    }

    // Håndter fejlbeskeder på login-siden
    const errorMessageElement = document.getElementById('errorMessage');
    if (errorMessageElement) {
        const errorMessage = errorMessageElement.getAttribute('data-message');
        if (errorMessage) {
            const userConfirmed = confirm(errorMessage + "\nVil du prøve igen?");
            if (!userConfirmed) {
                window.location.href = "/"; // Omdiriger til forsiden, hvis brugeren vælger "Cancel"
            }
        }
    }

    // Håndter "Slet konto"-knappen
    const deleteAccountForm = document.getElementById('deleteAccountForm');
    if (deleteAccountForm) {
        deleteAccountForm.addEventListener('submit', function (event) {
            const confirmResult = confirm("Er du sikker på, at du vil slette din konto? Dette kan ikke fortrydes.");
            if (!confirmResult) {
                event.preventDefault(); // Forhindrer formularen i at blive sendt
            }
        });
    }

    // Location toggle logic (only on settings.html)
    const locationToggle = document.getElementById('locationToggle');
    const locationStatus = document.getElementById('locationStatus');
    let locationPermission = document.getElementById('allowLocation')?.value === 'true'; // Hent initial værdi

    if (locationToggle && locationStatus) {
        function updateLocationUI(permission) {
            locationStatus.innerText = `Status: ${permission ? 'Tilladt' : 'Ikke tilladt'}`;
            locationToggle.innerText = permission ? 'Slå lokation fra' : 'Slå lokation til';
        }

        updateLocationUI(locationPermission); // Initial opdatering af UI

        // Tilføj event listener til knappen
        locationToggle.addEventListener('click', function handleLocationToggle() {
            const confirmMessage = locationPermission
                ? "Er du sikker på, at du vil slå lokationsadgang fra?"
                : "Er du sikker på, at du vil slå lokationsadgang til?";

            if (confirm(confirmMessage)) {
                saveLocationPermission(!locationPermission); // Skift tilladelse
            }
        });
    }

        // Stop klikpropagering på venneknapper
        document.querySelectorAll('.friend-action-btn').forEach(button => {
            button.addEventListener('click', function (event) {
                event.stopPropagation(); // Stop klik fra at propagere til <a>-elementet
            });
        });

    function saveLocationPermission(permission) {
        fetch('/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
            },
            body: `allow_location=${permission ? 'on' : ''}`
        })
        .then(response => {
            if (response.ok) {
                locationPermission = permission; // Opdater den lokale variabel
                updateLocationUI(locationPermission); // Opdater UI
            } else {
                alert('Kunne ikke gemme lokationsindstillingen. Prøv igen.');
            }
        })
        .catch(error => {
            console.error('Fejl under gemning af lokationsindstilling:', error);
            alert('Der opstod en fejl. Prøv igen senere.');
        });
    }

    const changeUsernameForm = document.getElementById('changeUsernameForm');
    if (changeUsernameForm) {
        changeUsernameForm.addEventListener('submit', function (event) {
            const confirmResult = confirmUsernameChange();
            if (!confirmResult) {
                event.preventDefault(); // Forhindrer formularen i at blive sendt
            }
        });
    }

    function confirmUsernameChange() {
        return confirm("Er du sikker på, at du vil ændre dit brugernavn? Der vil gå 7 dage, før du kan ændre det igen.");
    }

    // CSRF-token for POST requests
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Handle profile picture clicks
    document.querySelectorAll('.profile-picture').forEach(img => {
        img.addEventListener('click', function () {
            const userId = this.getAttribute('data-user-id');
            if (userId) {
                window.location.href = `/profile/${userId}`;
            } else {
                console.error('Bruger-ID mangler for dette profilbillede.');
            }
        });
    });

    if (!csrfToken) {
        console.warn('CSRF-token ikke fundet på denne side.');
        // Hvis CSRF-token ikke er nødvendig på denne side, kan du stoppe her
        return;
    }

        // Funktion til at håndtere venneknapper
// Funktion til at håndtere venneknapper
function handleFriendRequestButtons() {
    const friendActionButtons = document.querySelectorAll('.friend-action-btn');

    friendActionButtons.forEach(button => {
        button.addEventListener('click', function () {
            const action = this.getAttribute('data-action');
            const userId = this.getAttribute('data-user-id');
            const friendshipId = this.getAttribute('data-friendship-id');

            if (!action || (!userId && !friendshipId)) {
                console.error('Handling eller nødvendige data mangler.');
                alert('Der opstod en fejl. Prøv igen.');
                return;
            }

            // Send AJAX-forespørgsel til serveren
            fetch('/friend_action', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
                body: JSON.stringify({
                    action: action,
                    user_id: userId,
                    friendship_id: friendshipId
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        // Find venneanmodningscontaineren
                        const friendRequestContainer = document.getElementById('friend-request-container');
                        if (friendRequestContainer) {
                            if (data.new_status === 'accepted') {
                                // Opdater teksten og knapperne ved accept
                                friendRequestContainer.innerHTML = `
                                    <p class="text-muted">I har været venner siden ${data.friendship_created_at}.</p>
                                    <div id="friend-buttons-container">
                                        <button class="btn btn-danger mb-2 friend-action-btn" data-action="remove_friend" data-friendship-id="${data.friendship_id}">Fjern ven</button>
                                    </div>
                                `;
                            } else if (data.new_status === 'none') {
                                // Fjern hele containeren ved afvisning eller annullering
                                friendRequestContainer.remove();
                            } else if (data.new_status === 'pending_sent') {
                                // Opdater knapperne ved afsendelse af venneanmodning
                                friendRequestContainer.innerHTML = `
                                    <div id="friend-buttons-container">
                                        <button class="btn btn-warning mb-2 friend-action-btn" data-action="cancel_request" data-user-id="${userId}">Annuller anmodning</button>
                                    </div>
                                `;
                            } else if (data.new_status === 'pending_received') {
                                // Opdater knapperne ved modtagelse af venneanmodning
                                friendRequestContainer.innerHTML = `
                                    <p>Denne person har sendt dig en venneanmodning:</p>
                                    <div id="friend-buttons-container">
                                        <button class="btn btn-success mb-2 friend-action-btn" data-action="accept_request" data-friendship-id="${data.friendship_id}">Accepter</button>
                                        <button class="btn btn-danger mb-2 friend-action-btn" data-action="reject_request" data-friendship-id="${data.friendship_id}">Afvis</button>
                                    </div>
                                `;
                            }

                            // Genaktiver event listeners for de nye knapper
                            handleFriendRequestButtons();
                        }
                    } else {
                        alert(data.message || 'Noget gik galt. Prøv igen.');
                    }
                })
                .catch(error => {
                    console.error('Fejl:', error);
                    alert('Der opstod en fejl. Prøv igen senere.');
                });
        });
    });
}

// Kald funktionen for at tilføje event listeners til venneknapper
handleFriendRequestButtons();


    // Tjek om vi er på "Hvilken øl skal jeg drikke?"-siden
    if (document.getElementById('wheel')) {
        let beers = [];
        let colors = []; // Array til at gemme farverne

        // Tilføj event listener til formularen
        const beerForm = document.getElementById('beerForm');
        beerForm.addEventListener('submit', function (e) {
            e.preventDefault(); // Forhindrer standard formularindsendelse
            addBeer();
        });

        function addBeer() {
            const MAX_BEERS = 10; // Sæt en grænse for antallet af øl
            if (beers.length >= MAX_BEERS) {
                alert('Du kan ikke tilføje flere end 10 øl.');
                return;
            }

            const beerName = document.getElementById('beerName').value;
            if (beerName) {
                beers.push(beerName);
                colors.push(generateRandomColor());
                document.getElementById('beerName').value = '';
                drawWheel();
            }
        }

        function generateRandomColor() {
            let hue, saturation, lightness;
            let isSimilar;

            do {
                hue = Math.floor(Math.random() * 360); // Tilfældig farve (0-360 grader)
                saturation = Math.floor(Math.random() * 50) + 80; // Mætning mellem 80% og 100% for mere intensitet
                lightness = Math.floor(Math.random() * 20) + 40; // Lysstyrke mellem 40% og 60% for mere livlige farver

                // Tjek om farven er for tæt på en eksisterende farve
                isSimilar = colors.some(color => {
                    const [existingHue] = color.match(/\d+/g).map(Number); // Ekstraher hue fra HSL
                    return Math.abs(existingHue - hue) < 30; // Hvis hue er for tæt på, betragtes den som lignende
                });
            } while (isSimilar);

            return `hsl(${hue}, ${saturation}%, ${lightness}%)`;
        }

        function drawWheel() {
            const wheel = document.getElementById('wheel');
            wheel.innerHTML = ''; // Ryd tidligere segmenter

            if (beers.length === 0) {
                return; // Hvis der ikke er nogen øl, gør ingenting
            }

            const radius = 150; // Radius for hjulet
            const centerX = 150; // Center X
            const centerY = 150; // Center Y

            if (beers.length === 1) {
                // Hvis der kun er én øl, tegn en fuld cirkel
                const path = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                path.setAttribute("cx", centerX);
                path.setAttribute("cy", centerY);
                path.setAttribute("r", radius);
                path.setAttribute("fill", colors[0]); // Brug farven for den eneste øl
                path.setAttribute("stroke", "black");
                path.setAttribute("stroke-width", "2");
                wheel.appendChild(path);
        
                // Tilføj tekst i midten
                const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                text.setAttribute("x", centerX);
                text.setAttribute("y", centerY);
                text.setAttribute("fill", "#fff");
                text.setAttribute("font-size", "16");
                text.setAttribute("text-anchor", "middle");
                text.setAttribute("dominant-baseline", "middle");
                text.textContent = beers[0];
                wheel.appendChild(text);
        
                return; // Stop her, da vi kun har én øl
            }

            const segmentAngle = 360 / beers.length; // Beregn vinklen for hvert segment

            beers.forEach((beer, index) => {
                const startAngle = index * segmentAngle;
                const endAngle = startAngle + segmentAngle;

                const startX = centerX + radius * Math.cos((startAngle - 90) * Math.PI / 180);
                const startY = centerY + radius * Math.sin((startAngle - 90) * Math.PI / 180);
                const endX = centerX + radius * Math.cos((endAngle - 90) * Math.PI / 180);
                const endY = centerY + radius * Math.sin((endAngle - 90) * Math.PI / 180);

                const largeArcFlag = segmentAngle > 180 ? 1 : 0;

                const pathData = `
                    M ${centerX} ${centerY}
                    L ${startX} ${startY}
                    A ${radius} ${radius} 0 ${largeArcFlag} 1 ${endX} ${endY}
                    Z
                `;

                const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
                path.setAttribute("d", pathData);
                path.setAttribute("fill", colors[index]); // Brug den gemte farve
                path.setAttribute("stroke", "black"); // Sort kant mellem segmenterne
                path.setAttribute("stroke-width", "2"); // Tykkelsen på kanten
                wheel.appendChild(path);

                const textAngle = startAngle + segmentAngle / 2;
                const textX = centerX + (radius / 2) * Math.cos((textAngle - 90) * Math.PI / 180);
                const textY = centerY + (radius / 2) * Math.sin((textAngle - 90) * Math.PI / 180);

                const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
                text.setAttribute("x", textX);
                text.setAttribute("y", textY);
                text.setAttribute("fill", "#fff");
                text.setAttribute("font-size", "12");
                text.setAttribute("text-anchor", "middle");
                text.textContent = beer;
                wheel.appendChild(text);
            });
        }

        function spinWheel() {
            const wheel = document.getElementById('wheel');
            const randomAngle = Math.floor(Math.random() * 360); // Tilfældig vinkel mellem 0 og 360
            const baseRotations = 5; // Minimum antal fulde rotationer
            const totalRotation = randomAngle + 360 * baseRotations; // Tilføj fulde rotationer
            const spinDuration = 4; // Fast varighed i sekunder

            // Nulstil transition midlertidigt for at sikre ensartet animation
            wheel.style.transition = 'none';
            wheel.style.transform = `rotate(0deg)`; // Nulstil rotationen

            // Tving browseren til at genberegne stilen (reflow)
            setTimeout(() => {
                // Indstil CSS-transitionens varighed
                wheel.style.transition = `transform ${spinDuration}s ease-out`;

                // Anvend rotationen
                wheel.style.transform = `rotate(${totalRotation}deg)`;

                // Beregn det valgte segment efter animationen
                setTimeout(() => {
                    const selectedIndex = Math.floor((360 - (totalRotation % 360)) / (360 / beers.length)) % beers.length;
                    alert(`Du skal drikke: ${beers[selectedIndex]}`);
                }, spinDuration * 1000); // Vent til animationen er færdig
            }, 50); // Giv browseren tid til at nulstille stilen
        }

        // Tilføj event listeners
        document.querySelector('form').addEventListener('submit', function (e) {
            e.preventDefault();
            addBeer();
        });

        document.getElementById('spinWheelButton').addEventListener('click', spinWheel);
    }

    // Map initialization logic (only on map.html)
    if (document.getElementById('map')) {
        function initMap() {
            const defaultLocation = [56.2639, 9.5018];
            const map = L.map('map').setView(defaultLocation, 6);

            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            }).addTo(map);

            let currentView = "user";
            const markers = [];
            const userLogs = JSON.parse(document.getElementById('userLogs').textContent);
            const friendsLogs = JSON.parse(document.getElementById('friendsLogs').textContent);
            const allLogs = JSON.parse(document.getElementById('allLogs').textContent);

            function updateMap(logs) {
                markers.forEach(marker => map.removeLayer(marker));
                markers.length = 0;

                const groupedLogs = {};
                logs.forEach(log => {
                    if (log.latitude && log.longitude) {
                        const key = `${log.latitude},${log.longitude}`;
                        if (!groupedLogs[key]) {
                            groupedLogs[key] = { latitude: log.latitude, longitude: log.longitude, count: 0 };
                        }
                        groupedLogs[key].count += log.count;
                    }
                });

                Object.values(groupedLogs).forEach(group => {
                    const marker = L.marker([group.latitude, group.longitude])
                        .addTo(map)
                        .bindPopup("Antal øl drukket her: " + group.count);
                    markers.push(marker);
                });
            }

            function updateViewText() {
                const viewText = document.getElementById("viewText");
                viewText.textContent = currentView === "user"
                    ? "Kortet viser kun mine pile"
                    : currentView === "friends"
                        ? "Kortet viser kun venners pile"
                        : "Kortet viser alles pile";
            }

            updateMap(userLogs);
            updateViewText();

            document.getElementById("toggleViewButton").addEventListener("click", function () {
                if (currentView === "user") {
                    currentView = "friends";
                    updateMap(friendsLogs);
                    this.textContent = "Tryk for at vise alles pile";
                } else if (currentView === "friends") {
                    currentView = "all";
                    updateMap(allLogs);
                    this.textContent = "Tryk for kun at vise mine pile";
                } else {
                    currentView = "user";
                    updateMap(userLogs);
                    this.textContent = "Tryk for kun at vise venners pile";
                }
                updateViewText();
            });
        }

        initMap();
    }
});