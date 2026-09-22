window.dash_clientside = Object.assign({}, window.dash_clientside, {
    clientside: {
        bindTooltips: function(elements) {
            if(!elements || elements.length === 0) return window.dash_clientside.no_update;
            
            setTimeout(() => {
                var cy = document.getElementById('Project AETHERIS-cytoscape')._cyreg.cy;
                var container = cy.container();
                
                cy.nodes().forEach(function(node) {
                    let data = node.data();
                    // Prevent duplicate tippy instances on re-renders
                    if (node.scratch('_tippy')) { node.scratch('_tippy').destroy(); }
                    
                    let makeTippy = function(node, text){
                        let dummyDomEle = document.createElement('div');
                        let tip = tippy(dummyDomEle, {
                            // Compute absolute DOM coordinates directly to bypass Cytoscape-Popper extension sandboxing
                            getReferenceClientRect: () => {
                                let bb = node.renderedBoundingBox();
                                let rect = container.getBoundingClientRect();
                                return {
                                    width: bb.w,
                                    height: bb.h,
                                    top: rect.top + bb.y1,
                                    bottom: rect.top + bb.y2,
                                    left: rect.left + bb.x1,
                                    right: rect.left + bb.x2,
                                };
                            },
                            trigger: 'manual',
                            content: text,
                            allowHTML: true,
                            theme: 'aetheris-dark',
                            placement: 'top',
                            arrow: true,
                        });
                        return tip;
                    };

                    let content = `
                        <div class="tippy-payload">
                            <strong>${data.label || 'Unknown Node'}</strong><br>
                            MAC: ${data.mac || 'N/A'}<br>
                            FW: ${data.firmware || 'N/A'}<br>
                            Port: ${data.switchport || 'N/A'}
                        </div>`;
                    
                    let tip = makeTippy(node, content);
                    node.scratch('_tippy', tip);
                    
                    node.on('mouseover', () => tip.show());
                    node.on('mouseout', () => tip.hide());
                });
            }, 500); // Allow render cycle to complete
            return window.dash_clientside.no_update;
        }
    }
});