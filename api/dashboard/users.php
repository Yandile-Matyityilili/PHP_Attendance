<?php
header('Content-Type: application/json');
require_once __DIR__ . '/../../config/db.php';  // Make sure this path is correct

// Verify admin access (uncomment when ready)
// if (!isLoggedIn() || $_SESSION['user_role'] !== 'admin') {
//     http_response_code(403);
//     echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
//     exit;
// }

// Get all users with pagination
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['search'])) {
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;
    
    try {
        // Get users
        $stmt = $dbConnection->prepare("
            SELECT 
                user_id, 
                username,
                status, 
                email, 
                department,  
                created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ");
        $stmt->bind_param("ii", $limit, $offset);
        $stmt->execute();
        $result = $stmt->get_result();
        $users = $result->fetch_all(MYSQLI_ASSOC);
        
        // Get total count for pagination
        $totalResult = $dbConnection->query("SELECT COUNT(*) FROM users");
        $total = $totalResult->fetch_row()[0];
        
        echo json_encode([
            'success' => true,
            'data' => $users,
            'pagination' => [
                'total' => $total,
                'page' => $page,
                'limit' => $limit,
                'total_pages' => ceil($total / $limit)
            ]
        ]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}


//update the user
elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    // Get and validate JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid JSON data']);
        exit;
    }
    
    // Required field: user_id (to identify the user)
    if (empty($input['user_id'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing user_id']);
        exit;
    }
    
    // Optional fields (only update what's provided)
    $allowedFields = ['username', 'status', 'department', 'email'];
    $updates = [];
    $params = [];
    $types = '';
    
    foreach ($allowedFields as $field) {
        if (isset($input[$field])) {
            $updates[] = "$field = ?";
            $params[] = $input[$field];
            $types .= (is_int($input[$field]) ? 'i' : 's'); // 'i' for integer, 's' for string
        }
    }
    
    // No fields to update?
    if (empty($updates)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'No valid fields provided for update']);
        exit;
    }
    
    // Validate status (if provided)
    if (isset($input['status']) && !in_array($input['status'], ['On-site', 'Off-site'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid status (must be On-site or Off-site)']);
        exit;
    }
    
    // Validate email (if provided)
    if (isset($input['email']) && !filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid email format']);
        exit;
    }
    
    try {
        // Check if user exists first
        $checkStmt = $dbConnection->prepare("SELECT user_id FROM users WHERE user_id = ?");
        $checkStmt->bind_param("i", $input['user_id']);
        $checkStmt->execute();
        $checkStmt->store_result();
        
        if ($checkStmt->num_rows === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
            exit;
        }
        
        // Build dynamic SQL query
        $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE user_id = ?";
        $types .= 'i'; // For user_id (integer)
        $params[] = $input['user_id'];
        
        $stmt = $dbConnection->prepare($sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            echo json_encode([
                'success' => true,
                'message' => 'User updated successfully',
                'updated_fields' => array_keys($input) // Shows which fields were updated
            ]);
        } else {
            echo json_encode([
                'success' => true,
                'message' => 'No changes made (data may be the same)'
            ]);
        }
        
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Database error',
            'error' => $e->getMessage() // Remove in production for security
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($checkStmt)) $checkStmt->close();
    }
}

// Search users
elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['search'])) {
    $search = '%' . $_GET['search'] . '%';
    
    try {
        $stmt = $dbConnection->prepare("
            SELECT 
                user_id, 
                username,
                status,  
                department,
                email
            FROM users
            WHERE 
                username LIKE ? OR
                email LIKE ? OR
                department LIKE ?
            ORDER BY created_at DESC
            LIMIT 20
        ");
        $stmt->bind_param("sss", $search, $search, $search);
        $stmt->execute();
        $result = $stmt->get_result();
        $users = $result->fetch_all(MYSQLI_ASSOC);
        
        echo json_encode(['success' => true, 'data' => $users]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}


// Create new user
elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Validate required fields (without password)
    $requiredFields = ['username', 'email', 'department'];
    foreach ($requiredFields as $field) {
        if (empty($data[$field])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => "Missing required field: $field"]);
            exit;
        }
    }
    
    try {
        $stmt = $dbConnection->prepare("
            INSERT INTO users 
                (username, email, department, status, created_at)
            VALUES 
                (?, ?, ?, 'On-site', NOW())
        ");
        $stmt->bind_param("sss", 
            $data['username'], 
            $data['email'], 
            $data['department']
        );
        $stmt->execute();
        
        if ($stmt->affected_rows > 0) {
            $newUserId = $stmt->insert_id;
            echo json_encode([
                'success' => true,
                'message' => 'User created successfully',
                'user_id' => $newUserId
            ]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Failed to create user']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}


//delete user
elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // Get user_id from URL (e.g., /api/users?id=123)
    $user_id = isset($_GET['id']) ? (int)$_GET['id'] : null;
    
    // Validate input
    if (empty($user_id) || $user_id <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
        exit;
    }

    try {
        // Check if user exists first (optional but recommended)
        $checkStmt = $dbConnection->prepare("SELECT user_id FROM users WHERE user_id = ?");
        $checkStmt->bind_param("i", $user_id);
        $checkStmt->execute();
        $checkStmt->store_result();
        
        if ($checkStmt->num_rows === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
            exit;
        }

        // Soft delete (recommended) - sets deleted_at timestamp
        // $stmt = $dbConnection->prepare("UPDATE users SET deleted_at = NOW() WHERE user_id = ?");
        
        // Hard delete (permanently removes record)
        $stmt = $dbConnection->prepare("DELETE FROM users WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            echo json_encode(['success' => true, 'message' => 'User deleted']);
        } else {
            // Should rarely happen since we checked existence earlier
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Deletion failed']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'message' => 'Database error',
            'error' => $e->getMessage() // Remove in production for security
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($checkStmt)) $checkStmt->close();
    }
}
?>