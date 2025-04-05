from flask import Flask, render_template, redirect, url_for, request, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from functools import wraps
from flask_mail import Mail, Message
import csv
from flask import Flask, render_template, request, send_file, session, redirect, url_for, flash
import io
import matplotlib.pyplot as plt
import base64

  
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
# Gmail SMTP configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hrishi2186@gmail.com '  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'tofd ckjt iwzd keqc'  # Your Gmail password or app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'hrishi2186@gmail.com '  # Your email address

# Initialize Flask-Mail
mail = Mail(app)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'


# Default credentials
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = generate_password_hash("admin123")  # Hashed password for security


# Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(250), nullable=True)

# Model for Product
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    price = db.Column(db.Float, nullable=False)
    highlighted = db.Column(db.Boolean, default=False)
    image = db.Column(db.String(150), nullable=False)
    category_name = db.Column(db.String(100), nullable=False)  # New category field


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="Pending")

    # Relationships
    user = db.relationship('User', backref=db.backref('orders', lazy=True))
    product = db.relationship('Product', backref=db.backref('orders', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Admin, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not isinstance(current_user, Admin):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def load_user(user_id):
    user = Admin.query.get(int(user_id))  # Admin priority
    if not user:
        user = User.query.get(int(user_id))
    return user


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    if not user:
        user = Admin.query.get(int(user_id))
    return user


# Routes
@app.route('/')
def home():
    search_term = request.args.get('search', '')
    if search_term:
        products = Product.query.filter(
            Product.name.contains(search_term) | Product.category.contains(search_term)).all()
    else:
        products = Product.query.all()
    return render_template('user/product_list.html', products=products)

@app.route('/product_list', methods=['GET', 'POST'])
def product_list():
    search_term = request.args.get('search', '')
    if search_term:
        products = Product.query.filter(Product.name.contains(search_term) | Product.category_id.contains(search_term)).all()
    else:
        products = Product.query.all()
    return render_template('user/product_list.html', products=products)


# User Auth
@app.route('/login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid login credentials')
    return render_template('user/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        address = request.form['address']
        password = generate_password_hash(request.form['password'])
        user = User(name=name, email=email, address=address, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful! Please login.')
        return redirect(url_for('user_login'))
    return render_template('user/signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_login'))


@app.route('/my_orders')
@login_required  # Ensure the user is logged in
def my_orders():
    # Fetch orders for the current logged-in user
    orders = Order.query.filter_by(user_id=current_user.id).all()

    # Render a template with the order details
    return render_template('user/orders.html', orders=orders)


# Cart Management
@app.route('/cart', methods=['GET', 'POST'])
@login_required
def cart():
    # Query all cart items for the current user
    cart_items = (
        db.session.query(Cart, Product)
        .join(Product, Cart.product_id == Product.id)
        .filter(Cart.user_id == current_user.id)
        .all()
    )

    # Calculate total cart price
    cart_total = sum(item.Cart.quantity * item.Product.price for item in cart_items)

    # Prepare data for rendering
    cart_data = [
        {
            "product_name": item.Product.name,
            "quantity": item.Cart.quantity,
            "price": item.Product.price,
            "total": item.Cart.quantity * item.Product.price,
            "product_id": item.Product.id,
        }
        for item in cart_items
    ]

    return render_template('user/cart.html', cart=cart_data, cart_total=cart_total)


@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    product_id = request.form['product_id']
    quantity = int(request.form.get('quantity', 1))
    existing_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if existing_item:
        existing_item.quantity += quantity
    else:
        new_item = Cart(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(new_item)
    db.session.commit()
    flash('Added to cart!')
    return redirect(url_for('cart'))


@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    product_id = request.form.get('product_id')
    quantity = request.form.get('quantity')

    if not product_id or not quantity:
        flash('Invalid product or quantity.', 'danger')
        return redirect(url_for('cart'))

    try:
        cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity = int(quantity)
            db.session.commit()
            flash('Cart updated successfully.', 'success')
        else:
            flash('Cart item not found.', 'danger')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('cart'))


@app.route('/remove_from_cart', methods=['POST'])
@login_required
def remove_from_cart():
    product_id = request.form['product_id']
    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    return redirect(url_for('cart'))

# Checkout
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if current_user.is_authenticated:
        if request.method == 'POST':
            address = request.form['address']
            payment = request.form['payment']
            cart_items = Cart.query.filter_by(user_id=current_user.id).all()
            orders = []  # List to hold order objects
            for item in cart_items:
                product = Product.query.get(item.product_id)
                order = Order(
                    user_id=current_user.id,
                    product_id=item.product_id,
                    quantity=item.quantity,
                    total_price=item.quantity * product.price,
                    status="Confirmed"
                )
                db.session.add(order)
                orders.append(order)  # Add order to the list

            db.session.query(Cart).filter_by(user_id=current_user.id).delete()
            db.session.commit()

            # Send confirmation email with orders
            send_order_confirmation_email(current_user.email, orders)

            return redirect(url_for('order_confirmation'))
        return render_template('user/checkout.html', user=current_user)
    else:
        return redirect(url_for('login'))


def send_order_confirmation_email(user_email, orders):
    subject = 'Order Confirmation'
    body = 'Thank you for your order! Your order has been confirmed and is being processed.\n\n'

    # Retrieve the user and their address
    user = User.query.filter_by(email=user_email).first()
    if user:
        # Add the shipping address to the email
        if user.address:
            body += f"Shipping Address: {user.address}\n\n"
        else:
            body += "Shipping Address: Not available\n\n"

    # Add order details (products ordered)
    if orders:
        body += "Order Details:\n"
        total_order_value = 0  # Variable to calculate total order value
        for order in orders:
            product = Product.query.get(order.product_id)
            if product:  # Check if the product exists
                product_total_price = order.quantity * product.price
                total_order_value += product_total_price
                body += f"Product: {product.name}, Quantity: {order.quantity}, Total Price: {product_total_price}\n"
            else:
                body += f"Product ID {order.product_id} not found in the database.\n"

        # Add the total order value (sum of all products)
        body += f"\nTotal Order Value: {total_order_value}\n"

    else:
        body += "No items were ordered.\n"

    # Send email
    msg = Message(subject, recipients=[user_email])
    msg.body = body

    try:
        mail.send(msg)
    except Exception as e:
        print(f'Error sending email: {e}')


@app.route('/order_confirmation')
@login_required
def order_confirmation():
    orders = Order.query.filter_by(user_id=current_user.id).all()  # Get all orders for the user
    address = request.form.get('address')  # Assuming 'address' is passed from the checkout form
    payment = request.form.get('payment')  # Similarly, 'payment' comes from the form
    return render_template('user/confirmation.html', user=current_user, orders=orders, address=address, payment=payment)


@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()

        if admin and check_password_hash(admin.password, password):
            login_user(admin)
            session['is_admin'] = True  # Set admin session flag
            flash('Successfully logged in as admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')

    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """
    Admin Dashboard Route
    - Ensures the logged-in user is an admin.
    - Retrieves counts for users, products, and orders to display in the dashboard.
    """
    # Check if the session indicates an admin user
    if not session.get('is_admin'):
        flash('Access restricted to admins only.', 'danger')
        return redirect(url_for('user_login'))

    # Retrieve counts for dashboard statistics
    user_count = User.query.count()  # Total number of users
    product_count = Product.query.count()  # Total number of products
    order_count = Order.query.count()  # Total number of orders

    # Render the admin dashboard template with the counts
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        product_count=product_count,
        order_count=order_count
    )

@app.route('/admin/orders')
@login_required
def view_orders():
    if not session.get('is_admin'):
        flash('Access restricted to admins only.', 'danger')
        return redirect(url_for('user_login'))  # Ensure only admins can access this route
        # Query all orders and join with User and Product tables for details
    orders = db.session.query(Order, User, Product).join(User, Order.user_id == User.id).join(Product, Order.product_id == Product.id).all()

        # Prepare data to pass to the template
    order_details = []
    for order, user, product in orders:
        order_details.append({
                'order_id': order.id,
                'user_name': user.name,
                'user_email': user.email,
                'user_address': user.address,
                'product_name': product.name,
                'product_price': product.price,
                'quantity': order.quantity,
                'total_price': order.total_price,
                'status': order.status,
            })

        return render_template('admin/orders.html', orders=order_details)
    else:
        return redirect(url_for('unauthorized'))  # Redirect if not admin


# Manage Users
@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():

    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # Fetch user by ID
    user = User.query.get(user_id)
    if request.method == 'POST':
        # Update user details
        user.name = request.form['name']
        user.email = request.form['email']
        user.address = request.form['address']
        db.session.commit()
        return redirect(url_for('manage_users'))
    return render_template('admin/edit_user.html', user=user)


@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.')
    return redirect(url_for('manage_users'))

@app.route('/admin/manage_products', methods=['GET', 'POST'])
@login_required
def manage_products():
    products = Product.query.all()

    if request.method == 'POST':
        # Get data from the form
        name = request.form['name']
        description = request.form['description']
        category_name = request.form['category']
        price = float(request.form['price'])
        highlighted = 'highlighted' in request.form
          # Get category from form

        # Handle file upload
        image = request.files['image']
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

        # Create a new product and add it to the database
        product = Product(name=name, description=description, price=price, highlighted=highlighted, image=image_path, category_name=category_name)
        db.session.add(product)
        db.session.commit()

        flash('Product added successfully.')
        return redirect(url_for('manage_products'))

    return render_template('admin/manage_products.html', products=products)



# Route to delete a product
@app.route('/admin/delete_product/<int:product_id>', methods=['GET'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully.')
    return redirect(url_for('manage_products'))

@app.route('/admin/update_product/<int:product_id>', methods=['POST'])
@login_required
def update_product(product_id):

    product = Product.query.get(product_id)
    if product:
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.highlighted = 'highlighted' in request.form
        if 'image' in request.files and request.files['image'].filename:
            image = request.files['image']
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            image.save(image_path)
            product.image = image_path
        db.session.commit()
        flash('Product updated successfully.')
    return redirect(url_for('manage_products'))

@app.route('/admin/edit_product/<int:product_id>', methods=['GET'])
@login_required
def edit_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        flash('Product not found.')
        return redirect(url_for('manage_products'))
    return render_template('admin/edit.html', product=product)


@app.route('/admin/sales_report')
@login_required
def sales_report():
    # Query sales data: total sales per product
    sales_data = db.session.query(
        Product.name,
        db.func.sum(Order.total_price).label('total_sales'),
        db.func.sum(Order.quantity).label('total_quantity')
    ).join(Product, Product.id == Order.product_id) \
        .group_by(Product.name).all()

    # Generate a bar chart for sales data
    product_names = [data[0] for data in sales_data]
    total_sales = [data[1] for data in sales_data]

    plt.figure(figsize=(10, 6))
    plt.bar(product_names, total_sales, color='blue')
    plt.xlabel('Product Names')
    plt.ylabel('Total Sales')
    plt.title('Sales Report')
    plt.xticks(rotation=45)

    # Save the plot to a BytesIO object
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()
    plot_url = base64.b64encode(img.getvalue()).decode()

    return render_template(
        'admin/sales_report.html',
        sales_data=sales_data,
        plot_url=plot_url
    )


@app.route('/admin/download_sales_report', methods=['GET'])
@login_required
def download_sales_report():
    # Query sales data for CSV
    sales_data = db.session.query(
        Product.name,
        db.func.sum(Order.total_price).label('total_sales'),
        db.func.sum(Order.quantity).label('total_quantity')
    ).join(Product, Product.id == Order.product_id) \
        .group_by(Product.name).all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Product Name', 'Total Sales', 'Total Quantity'])

    for row in sales_data:
        writer.writerow([row[0], row[1], row[2]])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='sales_report.csv'  # Use download_name instead of attachment_filename
    )

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Ensure default admin exists
        if not Admin.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first():
            default_admin = Admin(username=DEFAULT_ADMIN_USERNAME, password=DEFAULT_ADMIN_PASSWORD)
            db.session.add(default_admin)
            db.session.commit()
        app.run(debug=True)

