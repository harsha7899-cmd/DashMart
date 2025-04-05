document.querySelectorAll('.update-quantity').forEach(button => {
    button.addEventListener('change', function() {
        const productId = this.dataset.productId;
        const quantity = this.value;

        fetch('/update_cart', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ product_id: productId, quantity: quantity }),
        }).then(response => response.json())
          .then(data => {
              if (data.success) {
                  location.reload();
              } else {
                  alert('Error updating cart');
              }
          });
    });
});
