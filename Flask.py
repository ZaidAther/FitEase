from flask import Flask, request, jsonify, url_for, render_template
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sqlite3
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from collections import defaultdict
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import secrets


app = Flask(__name__)
CORS(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'asadameen12123@gmail.com'
app.config['MAIL_PASSWORD'] = 'gxns txzf zbyw plbs'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)



secret_key = secrets.token_urlsafe(32)

serializer = URLSafeTimedSerializer(secret_key)

# Connect to SQLite database
conn = sqlite3.connect('user_data.db', check_same_thread=False)
cursor = conn.cursor()

# Create a table for users if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
conn.commit()

def load_data():
    df_nutrition = pd.read_csv('Nutrition.csv')
    df_exercises = pd.read_csv('GymExercisee.csv')
    
    df_nutrition['protein'] = df_nutrition['protein'].str.replace('g', '').astype(float)
    df_nutrition['carbohydrate'] = df_nutrition['carbohydrate'].str.replace('g', '').astype(float)
    df_nutrition['total_fat'] = df_nutrition['total_fat'].str.replace('g', '').astype(float)
    df_nutrition['fat'] = df_nutrition['fat'].str.replace('g', '').astype(float)

    scaler = StandardScaler()
    nutrition_scaled = scaler.fit_transform(df_nutrition[['calories', 'protein', 'carbohydrate', 'total_fat', 'fat']])
    kmeans = KMeans(n_clusters=5, random_state=42, n_init=10)
    df_nutrition['cluster'] = kmeans.fit_predict(nutrition_scaled)
    
    return df_nutrition, df_exercises

df_nutrition, df_exercises = load_data()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    hashed_password = generate_password_hash(password)

    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        return jsonify({'message': 'User created successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'message': 'User already exists'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    if user and check_password_hash(user[2], password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/password_reset_request', methods=['POST'])
def password_reset_request():
    email = request.json['email']
    token = serializer.dumps(email, salt='email-reset')
    link = url_for('reset_password', token=token, _external=True)

    msg = Message('Reset Your Password', sender='your-email@gmail.com', recipients=[email])
    msg.body = 'Follow this link to reset your password: {}'.format(link)
    mail.send(msg)

    return jsonify({'message': 'Password reset email sent'})

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'GET':
        # Render the reset password HTML template
        return render_template('reset_password.html')

    elif request.method == 'POST':
        try:
            email = serializer.loads(token, salt='email-reset', max_age=3600)
        except SignatureExpired:
            return jsonify({'message': 'The password reset link is expired'}), 400

        new_password = request.json['password']
        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
        conn.commit()
        return jsonify({'message': 'Password updated successfully'})

    return 'Invalid method', 405




def recommend_meal_plan(cluster_id, days=7):
    meal_plan = defaultdict(lambda: defaultdict(dict))
    try:
        for day in range(1, days + 1):
            for meal_time in ['breakfast', 'lunch', 'dinner']:
                # Filter the dataframe by cluster
                filtered_meals = df_nutrition[df_nutrition['cluster'] == cluster_id]
                
                if filtered_meals.empty:
                    raise ValueError(f"No meals available for cluster_id {cluster_id}")
                
                meal = filtered_meals.sample(n=1)
                meal_plan[f"Day {day}"][meal_time] = {
                    'name': meal.iloc[0]['name'],
                    'calories': int(meal.iloc[0]['calories']),
                    'protein': float(meal.iloc[0]['protein']),
                    'carbohydrate': float(meal.iloc[0]['carbohydrate']),
                    'fat': float(meal.iloc[0]['total_fat'])
                }
    except Exception as e:
        print(f"Error in recommend_meal_plan: {str(e)}")
        # Optionally, return a message or a default meal plan here
        # For example:
        # meal_plan['error'] = "Unable to generate meal plan"
    return meal_plan


def recommend_workout_plan(muscle_groups, weight, height, age, gender, fitness_goal, workout_intensity, activity_level):
    workout_plan = defaultdict(lambda: defaultdict(dict))
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    for index, day in enumerate(day_names):
        for muscle_group in muscle_groups:
            # Filter exercises by muscle group
            exercises = df_exercises[df_exercises['muscle_gp'].str.contains(muscle_group, case=False, na=False)]

            if not exercises.empty:
                # Sort exercises by rating
                sorted_exercises = exercises.sort_values(by='Rating', ascending=False)
                
                # Cycling through the top 3 exercises for variety
                top_exercises = sorted_exercises.head(3)
                selected_exercise = top_exercises.iloc[index % len(top_exercises)]

                # Add exercise details to the workout plan
                workout_plan[day][muscle_group.capitalize()] = {
                    'Exercise_Name': selected_exercise['Exercise_Name'],
                    'Description': selected_exercise['Description'],
                    'Equipment': selected_exercise['equipment_details'],  # Assuming the column name is corrected
                    'Exercise_Video': selected_exercise['Exercise_Video'],
                    'Rating': selected_exercise['Rating']
                }
            else:
                # If no exercises are available for the muscle group, mark it as not available
                workout_plan[day][muscle_group.capitalize()] = {
                    'Exercise_Name': 'No available exercise',
                    'Description': 'N/A',
                    'Equipment': 'N/A',
                    'Exercise_Video': 'N/A',
                    'Rating': 'N/A'
                }
    return workout_plan



# Route for recommending meal plan
@app.route('/recommend_meal_plan', methods=['POST'])
def get_recommend_meal_plan():
    data = request.json
    cluster_id = data.get('cluster_id', 0)
    try:
        meal_plan = recommend_meal_plan(cluster_id)
        if 'error' in meal_plan:
            return jsonify({'error': meal_plan['error']}), 400
        return jsonify(meal_plan)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Update the /recommend_workout_plan endpoint to accept a list of muscle groups
@app.route('/recommend_workout_plan', methods=['POST'])
def get_recommend_workout_plan():
    data = request.json
    muscle_groups = data.get('muscle_groups', [])  # List of muscle groups
    weight = data.get('weight')
    height = data.get('height')
    age = data.get('age')
    gender = data.get('gender')
    fitness_goal = data.get('fitness_goal')
    workout_intensity = data.get('workout_intensity')
    activity_level = data.get('activity_level')
    workout_plan = recommend_workout_plan(muscle_groups, weight, height, age, gender, fitness_goal, workout_intensity, activity_level)
    return jsonify(workout_plan)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')