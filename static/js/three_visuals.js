/**
 * Cyber-Intelligence 3D WebGL Visualizations
 * Powered by Three.js
 */

// Global state for 3D visualizations
const CyberVisuals = {
    // 1. Particle Constellation for Background
    initLoginBackground: function(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 1, 1000);
        camera.position.z = 400;

        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(container.clientWidth, container.clientHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        // Particle configuration
        const particleCount = 120;
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const velocities = [];

        for (let i = 0; i < particleCount; i++) {
            // Random positions in a box
            positions[i * 3] = (Math.random() - 0.5) * 800;
            positions[i * 3 + 1] = (Math.random() - 0.5) * 600;
            positions[i * 3 + 2] = (Math.random() - 0.5) * 400;

            // Random velocities
            velocities.push({
                x: (Math.random() - 0.5) * 0.5,
                y: (Math.random() - 0.5) * 0.5,
                z: (Math.random() - 0.5) * 0.5
            });
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

        // Create particles material (glowing cyan dots)
        const material = new THREE.PointsMaterial({
            color: 0x00f0ff,
            size: 4,
            transparent: true,
            opacity: 0.8,
            blending: THREE.AdditiveBlending
        });

        const particleSystem = new THREE.Points(geometry, material);
        scene.add(particleSystem);

        // Lines linking close particles
        const lineMaterial = new THREE.LineBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.15,
            blending: THREE.AdditiveBlending
        });

        let lineSegments;

        // Interaction state
        let mouseX = 0, mouseY = 0;
        document.addEventListener('mousemove', (e) => {
            mouseX = (e.clientX - window.innerWidth / 2) * 0.05;
            mouseY = (e.clientY - window.innerHeight / 2) * 0.05;
        });

        // Animation Loop
        function animate() {
            requestAnimationFrame(animate);

            // Update particle positions
            const positionsAttr = particleSystem.geometry.attributes.position;
            const linePositions = [];

            for (let i = 0; i < particleCount; i++) {
                // Move particle
                positionsAttr.array[i * 3] += velocities[i].x;
                positionsAttr.array[i * 3 + 1] += velocities[i].y;
                positionsAttr.array[i * 3 + 2] += velocities[i].z;

                // Bounce off boundaries
                if (Math.abs(positionsAttr.array[i * 3]) > 400) velocities[i].x *= -1;
                if (Math.abs(positionsAttr.array[i * 3 + 1]) > 300) velocities[i].y *= -1;
                if (Math.abs(positionsAttr.array[i * 3 + 2]) > 200) velocities[i].z *= -1;
            }
            positionsAttr.needsUpdate = true;

            // Generate lines for close points
            if (lineSegments) scene.remove(lineSegments);

            for (let i = 0; i < particleCount; i++) {
                const x1 = positionsAttr.array[i * 3];
                const y1 = positionsAttr.array[i * 3 + 1];
                const z1 = positionsAttr.array[i * 3 + 2];

                for (let j = i + 1; j < particleCount; j++) {
                    const x2 = positionsAttr.array[j * 3];
                    const y2 = positionsAttr.array[j * 3 + 1];
                    const z2 = positionsAttr.array[j * 3 + 2];

                    const dist = Math.sqrt((x1-x2)**2 + (y1-y2)**2 + (z1-z2)**2);
                    if (dist < 100) {
                        linePositions.push(x1, y1, z1);
                        linePositions.push(x2, y2, z2);
                    }
                }
            }

            if (linePositions.length > 0) {
                const lineGeometry = new THREE.BufferGeometry();
                lineGeometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
                lineSegments = new THREE.LineSegments(lineGeometry, lineMaterial);
                scene.add(lineSegments);
            }

            // Camera movement based on mouse
            camera.position.x += (mouseX - camera.position.x) * 0.05;
            camera.position.y += (-mouseY - camera.position.y) * 0.05;
            camera.lookAt(scene.position);

            renderer.render(scene, camera);
        }

        animate();

        // Handle resize
        window.addEventListener('resize', () => {
            camera.aspect = container.clientWidth / container.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(container.clientWidth, container.clientHeight);
        });
    },

    // 2. Glowing Shield representing API Security Engine
    initDashboardShield: function(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(45, container.clientWidth / container.clientHeight, 1, 1000);
        camera.position.z = 250;

        const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(container.clientWidth, container.clientHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        // Core Glowing Sphere
        const sphereGeom = new THREE.SphereGeometry(45, 24, 24);
        const sphereMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            wireframe: true,
            transparent: true,
            opacity: 0.12
        });
        const coreSphere = new THREE.Mesh(sphereGeom, sphereMat);
        scene.add(coreSphere);

        // Outer Ring 1 (Cyber Torus)
        const torusGeom = new THREE.TorusGeometry(60, 1.5, 8, 48);
        const torusMat = new THREE.MeshBasicMaterial({
            color: 0x10b981,
            transparent: true,
            opacity: 0.6
        });
        const ring1 = new THREE.Mesh(torusGeom, torusMat);
        scene.add(ring1);

        // Outer Ring 2 (Intersecting)
        const ring2 = ring1.clone();
        ring2.material = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.4
        });
        ring2.rotation.x = Math.PI / 2;
        scene.add(ring2);

        // Orbiting particles (Data Streams)
        const particleCount = 40;
        const particlesGeom = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        const orbitAngles = [];
        const orbitSpeeds = [];
        const orbitRadii = [];

        for (let i = 0; i < particleCount; i++) {
            orbitAngles.push(Math.random() * Math.PI * 2);
            orbitSpeeds.push(0.01 + Math.random() * 0.02);
            orbitRadii.push(50 + Math.random() * 20);

            positions[i * 3] = Math.cos(orbitAngles[i]) * orbitRadii[i];
            positions[i * 3 + 1] = Math.sin(orbitAngles[i]) * orbitRadii[i];
            positions[i * 3 + 2] = (Math.random() - 0.5) * 30;
        }

        particlesGeom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        const particlesMat = new THREE.PointsMaterial({
            color: 0x00f0ff,
            size: 3,
            transparent: true,
            opacity: 0.9,
            blending: THREE.AdditiveBlending
        });
        const orbitParticles = new THREE.Points(particlesGeom, particlesMat);
        scene.add(orbitParticles);

        // Add subtle light
        const light = new THREE.PointLight(0x00f0ff, 1, 100);
        light.position.set(0, 0, 0);
        scene.add(light);

        // Interaction
        let targetRotationX = 0;
        let targetRotationY = 0;
        container.addEventListener('mousemove', (e) => {
            const rect = container.getBoundingClientRect();
            const x = (e.clientX - rect.left) / container.clientWidth - 0.5;
            const y = (e.clientY - rect.top) / container.clientHeight - 0.5;
            targetRotationX = y * 0.5;
            targetRotationY = x * 0.5;
        });

        // Animation loop
        function animate() {
            requestAnimationFrame(animate);

            // Core rotations
            coreSphere.rotation.y += 0.005;
            coreSphere.rotation.x += 0.002;
            
            ring1.rotation.y += 0.01;
            ring1.rotation.x += 0.003;
            
            ring2.rotation.y -= 0.008;
            ring2.rotation.z += 0.004;

            // Update orbiting particles
            const positionsAttr = orbitParticles.geometry.attributes.position;
            for (let i = 0; i < particleCount; i++) {
                orbitAngles[i] += orbitSpeeds[i];
                positionsAttr.array[i * 3] = Math.cos(orbitAngles[i]) * orbitRadii[i];
                positionsAttr.array[i * 3 + 1] = Math.sin(orbitAngles[i]) * orbitRadii[i] * Math.sin(orbitAngles[i] * 0.1);
                positionsAttr.array[i * 3 + 2] = Math.sin(orbitAngles[i]) * 15;
            }
            positionsAttr.needsUpdate = true;

            // Apply interactive rotations
            scene.rotation.x += (targetRotationX - scene.rotation.x) * 0.05;
            scene.rotation.y += (targetRotationY - scene.rotation.y) * 0.05;

            renderer.render(scene, camera);
        }

        animate();

        // Handle resize
        window.addEventListener('resize', () => {
            camera.aspect = container.clientWidth / container.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(container.clientWidth, container.clientHeight);
        });
    },

    // 3. 3D Force-Directed Fraud Connection Network
    initNetwork3DGraph: function(containerId, appsData, onNodeSelect) {
        const container = document.getElementById(containerId);
        if (!container) return;

        // Create canvas inside container
        container.innerHTML = '';
        
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(50, container.clientWidth / container.clientHeight, 1, 2000);
        camera.position.set(0, 0, 500);

        const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
        renderer.setClearColor(0x080c14, 1);
        renderer.setSize(container.clientWidth, container.clientHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        // Setup OrbitControls
        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.maxDistance = 1000;
        controls.minDistance = 100;

        // Process application data into a node-link model
        const nodes = [];
        const links = [];
        const nodeMap = {};

        // Helper to add nodes
        function addNode(id, label, type, val, riskScore = 0, extra = {}) {
            if (nodeMap[id]) return nodeMap[id];
            
            const node = {
                id,
                label,
                type, // 'app', 'aadhaar', 'phone', 'district'
                val,  // Size/Importance
                riskScore,
                extra,
                x: (Math.random() - 0.5) * 300,
                y: (Math.random() - 0.5) * 300,
                z: (Math.random() - 0.5) * 300,
                vx: 0, vy: 0, vz: 0
            };
            nodes.push(node);
            nodeMap[id] = node;
            return node;
        }

        // Parse appsData (which should be an array of application dicts)
        appsData.forEach(app => {
            const risk = app.risk_score || 0;
            // App node
            const appNode = addNode(`app_${app.id}`, app.name, 'app', 12, risk, {
                aadhaar: app.aadhaar,
                phone: app.phone,
                scheme: app.scheme,
                income: app.income,
                classification: app.classification || 'REVIEW'
            });

            // Share Aadhaar node
            const aadhNode = addNode(`aadhaar_${app.aadhaar}`, `Aadhaar: ${app.aadhaar.substring(0,4)}...`, 'aadhaar', 8, risk > 60 ? risk : 0);
            links.push({ source: appNode, target: aadhNode, type: 'aadhaar' });

            // Share Phone node
            const phoneNode = addNode(`phone_${app.phone}`, `Phone: ${app.phone}`, 'phone', 8, risk > 60 ? risk : 0);
            links.push({ source: appNode, target: phoneNode, type: 'phone' });

            // District node (low weight connection)
            if (app.district) {
                const distNode = addNode(`dist_${app.district}`, `District: ${app.district}`, 'district', 6, 0);
                links.push({ source: appNode, target: distNode, type: 'district' });
            }
        });

        // 3D Objects mappings
        const nodeGroup = new THREE.Group();
        const linkGroup = new THREE.Group();
        scene.add(nodeGroup);
        scene.add(linkGroup);

        const nodeMeshes = [];
        const linkLines = [];

        // Materials cache
        const colors = {
            app_APPROVE: 0x10b981, // Emerald
            app_REVIEW: 0xf59e0b,  // Amber
            app_REJECT: 0xef4444,  // Crimson
            aadhaar: 0x00f0ff,     // Cyber blue
            phone: 0xa855f7,       // Purple
            district: 0x64748b     // Grey
        };

        // Create Node Meshes
        nodes.forEach(node => {
            let color = colors[node.type] || 0xffffff;
            if (node.type === 'app') {
                const cStatus = node.extra.classification || 'REVIEW';
                color = colors[`app_${cStatus}`] || colors.app_REVIEW;
            }

            const geometry = new THREE.SphereGeometry(node.val, 16, 16);
            const material = new THREE.MeshPhongMaterial({
                color: color,
                emissive: color,
                emissiveIntensity: 0.25,
                shininess: 30
            });
            const mesh = new THREE.Mesh(geometry, material);
            mesh.userData = { nodeData: node };
            nodeGroup.add(mesh);
            nodeMeshes.push(mesh);
        });

        // Lights
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.4);
        scene.add(ambientLight);
        
        const dirLight1 = new THREE.DirectionalLight(0xffffff, 0.8);
        dirLight1.position.set(200, 400, 300);
        scene.add(dirLight1);

        const dirLight2 = new THREE.DirectionalLight(0x00f0ff, 0.4);
        dirLight2.position.set(-200, -400, -300);
        scene.add(dirLight2);

        // Simple 3D Force-Directed Simulation
        const springLength = 80;
        const kAttract = 0.04;
        const kRepel = 1200;
        const damping = 0.85;

        function stepSimulation() {
            // 1. Repulsion between all node pairs
            for (let i = 0; i < nodes.length; i++) {
                const n1 = nodes[i];
                for (let j = i + 1; j < nodes.length; j++) {
                    const n2 = nodes[j];
                    const dx = n2.x - n1.x;
                    const dy = n2.y - n1.y;
                    const dz = n2.z - n1.z;
                    const distSq = dx*dx + dy*dy + dz*dz + 0.1;
                    const dist = Math.sqrt(distSq);

                    // Force inversely proportional to distance squared
                    const force = kRepel / distSq;
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    const fz = (dz / dist) * force;

                    n1.vx -= fx; n1.vy -= fy; n1.vz -= fz;
                    n2.vx += fx; n2.vy += fy; n2.vz += fz;
                }
            }

            // 2. Attraction along links
            links.forEach(link => {
                const n1 = link.source;
                const n2 = link.target;
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const dz = n2.z - n1.z;
                const dist = Math.sqrt(dx*dx + dy*dy + dz*dz) + 0.1;

                // Spring force
                const force = kAttract * (dist - springLength);
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                const fz = (dz / dist) * force;

                n1.vx += fx; n1.vy += fy; n1.vz += fz;
                n2.vx -= fx; n2.vy -= fy; n2.vz -= fz;
            });

            // 3. Update positions, apply damping, keep near center
            nodes.forEach(node => {
                node.vx *= damping;
                node.vy *= damping;
                node.vz *= damping;

                // Center gravity
                node.vx -= node.x * 0.005;
                node.vy -= node.y * 0.005;
                node.vz -= node.z * 0.005;

                node.x += node.vx;
                node.y += node.vy;
                node.z += node.vz;
            });
        }

        // Raycasting for Interaction
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();
        let hoveredMesh = null;

        container.addEventListener('mousemove', (event) => {
            const rect = renderer.domElement.getBoundingClientRect();
            mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
            mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        });

        container.addEventListener('click', () => {
            if (hoveredMesh && onNodeSelect) {
                onNodeSelect(hoveredMesh.userData.nodeData);
            }
        });

        // Render & Sim Loop
        function animate() {
            requestAnimationFrame(animate);

            // Step physics simulation
            for (let i = 0; i < 4; i++) { // run multiple steps per frame for faster stabilization
                stepSimulation();
            }

            // Update mesh positions
            nodeMeshes.forEach(mesh => {
                const data = mesh.userData.nodeData;
                mesh.position.set(data.x, data.y, data.z);
            });

            // Update/Create Link Lines
            linkGroup.innerHTML = ''; // clear group
            while(linkGroup.children.length > 0){
                linkGroup.remove(linkGroup.children[0]);
            }

            const linePositions = [];
            const lineColors = [];
            
            links.forEach(link => {
                linePositions.push(link.source.x, link.source.y, link.source.z);
                linePositions.push(link.target.x, link.target.y, link.target.z);
                
                // Color lines by link type
                let c = new THREE.Color(0x334155); // Default grey
                if (link.type === 'aadhaar') c.setHex(0x00f0ff);
                if (link.type === 'phone') c.setHex(0xa855f7);
                lineColors.push(c.r, c.g, c.b);
                lineColors.push(c.r, c.g, c.b);
            });

            if (linePositions.length > 0) {
                const lineGeom = new THREE.BufferGeometry();
                lineGeom.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3));
                lineGeom.setAttribute('color', new THREE.Float32BufferAttribute(lineColors, 3));
                const lineMat = new THREE.LineBasicMaterial({
                    vertexColors: true,
                    transparent: true,
                    opacity: 0.4
                });
                const linkLinesMesh = new THREE.LineSegments(lineGeom, lineMat);
                linkGroup.add(linkLinesMesh);
            }

            // Raycast check
            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(nodeMeshes);

            if (intersects.length > 0) {
                if (hoveredMesh !== intersects[0].object) {
                    // Reset old hover
                    if (hoveredMesh) {
                        hoveredMesh.scale.set(1, 1, 1);
                        hoveredMesh.material.emissiveIntensity = 0.25;
                    }
                    // Apply new hover
                    hoveredMesh = intersects[0].object;
                    hoveredMesh.scale.set(1.4, 1.4, 1.4);
                    hoveredMesh.material.emissiveIntensity = 0.8;
                    
                    // Style cursor
                    container.style.cursor = 'pointer';
                }
            } else {
                if (hoveredMesh) {
                    hoveredMesh.scale.set(1, 1, 1);
                    hoveredMesh.material.emissiveIntensity = 0.25;
                    hoveredMesh = null;
                    container.style.cursor = 'default';
                }
            }

            controls.update();
            renderer.render(scene, camera);
        }

        animate();

        // Handle resize
        window.addEventListener('resize', () => {
            camera.aspect = container.clientWidth / container.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(container.clientWidth, container.clientHeight);
        });
    }
};
