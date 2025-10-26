<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

// Error handling
error_reporting(0);
ini_set('display_errors', 0);

// Start execution time
$start_time = microtime(true);

class RealPaymentAPI {
    private $db;
    private $supported_gateways = ['stripe', 'paypal', 'square', 'authorize'];
    
    public function __construct() {
        $this->initializeDatabase();
    }
    
    private function initializeDatabase() {
        try {
            $this->db = new SQLite3('real_payments.db');
            
            // Create tables
            $this->db->exec('CREATE TABLE IF NOT EXISTS payment_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                site TEXT,
                card_hash TEXT,
                card_type TEXT,
                gateway TEXT,
                status TEXT,
                amount REAL,
                currency TEXT,
                transaction_id TEXT,
                response_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )');
            
            $this->db->exec('CREATE TABLE IF NOT EXISTS rate_limits (
                ip TEXT PRIMARY KEY,
                request_count INTEGER,
                last_request DATETIME
            )');
            
            $this->db->exec('CREATE TABLE IF NOT EXISTS card_bins (
                bin TEXT PRIMARY KEY,
                card_type TEXT,
                bank_name TEXT,
                country TEXT
            )');
            
            // Insert sample BIN data
            $this->initializeBINData();
            
        } catch (Exception $e) {
            error_log("Database error: " . $e->getMessage());
        }
    }
    
    private function initializeBINData() {
        // Sample BIN data for major card types
        $sample_bins = [
            ['411111', 'visa', 'Chase', 'US'],
            ['511111', 'mastercard', 'Bank of America', 'US'],
            ['371111', 'amex', 'American Express', 'US'],
            ['361111', 'diners', 'Citibank', 'US'],
            ['351111', 'jcb', 'JCB', 'JP'],
            ['601111', 'discover', 'Discover', 'US'],
            ['541111', 'mastercard', 'Wells Fargo', 'US'],
            ['451111', 'visa', 'Capital One', 'US']
        ];
        
        foreach ($sample_bins as $bin) {
            $stmt = $this->db->prepare('INSERT OR IGNORE INTO card_bins (bin, card_type, bank_name, country) VALUES (?, ?, ?, ?)');
            $stmt->bindValue(1, $bin[0], SQLITE3_TEXT);
            $stmt->bindValue(2, $bin[1], SQLITE3_TEXT);
            $stmt->bindValue(3, $bin[2], SQLITE3_TEXT);
            $stmt->bindValue(4, $bin[3], SQLITE3_TEXT);
            $stmt->execute();
        }
    }
    
    public function checkRateLimit($ip) {
        $stmt = $this->db->prepare('SELECT * FROM rate_limits WHERE ip = :ip');
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        
        $max_requests = 25; // 25 requests per minute
        $time_window = 60;
        
        if ($result) {
            $last_time = strtotime($result['last_request']);
            if ((time() - $last_time) < $time_window) {
                if ($result['request_count'] >= $max_requests) {
                    return false;
                }
                // Update count
                $stmt = $this->db->prepare('UPDATE rate_limits SET request_count = request_count + 1 WHERE ip = :ip');
                $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
                $stmt->execute();
            } else {
                // Reset counter
                $stmt = $this->db->prepare('UPDATE rate_limits SET request_count = 1, last_request = datetime("now") WHERE ip = :ip');
                $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
                $stmt->execute();
            }
        } else {
            // First request
            $stmt = $this->db->prepare('INSERT INTO rate_limits (ip, request_count, last_request) VALUES (:ip, 1, datetime("now"))');
            $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
            $stmt->execute();
        }
        
        return true;
    }
    
    public function validateCC($cc) {
        $parts = explode('|', $cc);
        if (count($parts) < 4) {
            return ['valid' => false, 'error' => 'Invalid format. Use: number|month|year|cvv'];
        }
        
        list($number, $month, $year, $cvv) = $parts;
        
        // Clean data
        $number = preg_replace('/\s+/', '', $number);
        $month = trim($month);
        $year = trim($year);
        $cvv = trim($cvv);
        
        // Card number validation
        if (!is_numeric($number) || strlen($number) < 13 || strlen($number) > 19) {
            return ['valid' => false, 'error' => 'Invalid card number length'];
        }
        
        // Month validation
        if (!is_numeric($month) || $month < 1 || $month > 12) {
            return ['valid' => false, 'error' => 'Invalid month (1-12)'];
        }
        
        // Year validation
        if (strlen($year) == 2) {
            $year = '20' . $year;
        }
        
        $current_year = date('Y');
        $current_month = date('m');
        
        if (!is_numeric($year) || $year < $current_year) {
            return ['valid' => false, 'error' => 'Card expired'];
        }
        
        if ($year == $current_year && $month < $current_month) {
            return ['valid' => false, 'error' => 'Card expired this month'];
        }
        
        // CVV validation
        if (!is_numeric($cvv) || strlen($cvv) < 3 || strlen($cvv) > 4) {
            return ['valid' => false, 'error' => 'Invalid CVV'];
        }
        
        // Luhn algorithm check
        if (!$this->luhnCheck($number)) {
            return ['valid' => false, 'error' => 'Invalid card number (Luhn check failed)'];
        }
        
        return [
            'valid' => true,
            'number' => $number,
            'month' => str_pad($month, 2, '0', STR_PAD_LEFT),
            'year' => $year,
            'cvv' => $cvv,
            'last4' => substr($number, -4),
            'expiry' => str_pad($month, 2, '0', STR_PAD_LEFT) . '/' . substr($year, 2, 2)
        ];
    }
    
    private function luhnCheck($number) {
        $number = strrev(preg_replace('/[^\d]/', '', $number));
        $sum = 0;
        
        for ($i = 0, $j = strlen($number); $i < $j; $i++) {
            if (($i % 2) == 0) {
                $val = $number[$i];
            } else {
                $val = $number[$i] * 2;
                if ($val > 9) {
                    $val -= 9;
                }
            }
            $sum += $val;
        }
        
        return (($sum % 10) === 0);
    }
    
    public function detectCardInfo($number) {
        $number = preg_replace('/\s+/', '', $number);
        
        // Check BIN database first
        $bin = substr($number, 0, 6);
        $stmt = $this->db->prepare('SELECT * FROM card_bins WHERE bin = :bin');
        $stmt->bindValue(':bin', $bin, SQLITE3_TEXT);
        $result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        
        if ($result) {
            return [
                'card_type' => $result['card_type'],
                'bank_name' => $result['bank_name'],
                'country' => $result['country'],
                'bin' => $bin
            ];
        }
        
        // Fallback to pattern matching
        $first_two = substr($number, 0, 2);
        $first_four = substr($number, 0, 4);
        
        $card_patterns = [
            'visa' => ['pattern' => '/^4[0-9]{12}(?:[0-9]{3})?$/', 'bins' => ['4']],
            'mastercard' => ['pattern' => '/^5[1-5][0-9]{14}$/', 'bins' => ['51', '52', '53', '54', '55']],
            'amex' => ['pattern' => '/^3[47][0-9]{13}$/', 'bins' => ['34', '37']],
            'discover' => ['pattern' => '/^6(?:011|5[0-9]{2})[0-9]{12}$/', 'bins' => ['6011', '65']],
            'jcb' => ['pattern' => '/^(?:2131|1800|35\d{3})\d{11}$/', 'bins' => ['35']],
            'diners' => ['pattern' => '/^3(?:0[0-5]|[68][0-9])[0-9]{11}$/', 'bins' => ['300', '301', '302', '303', '304', '305', '36', '38']]
        ];
        
        foreach ($card_patterns as $type => $info) {
            if (preg_match($info['pattern'], $number)) {
                return [
                    'card_type' => $type,
                    'bank_name' => 'Unknown Bank',
                    'country' => 'International',
                    'bin' => $bin
                ];
            }
        }
        
        return [
            'card_type' => 'unknown',
            'bank_name' => 'Unknown Bank',
            'country' => 'International',
            'bin' => $bin
        ];
    }
    
    public function processPayment($site, $cc, $amount = '1.00', $currency = 'usd') {
        // Select gateway based on site
        $gateway = $this->selectGateway($site);
        
        // Get card info
        $card_info = $this->detectCardInfo($cc['number']);
        
        // Realistic processing delay
        usleep(mt_rand(200000, 800000)); // 200-800ms
        
        // Process with selected gateway
        switch($gateway) {
            case 'stripe':
                return $this->processStripe($cc, $amount, $currency, $card_info);
            case 'paypal':
                return $this->processPayPal($cc, $amount, $currency, $card_info);
            case 'square':
                return $this->processSquare($cc, $amount, $currency, $card_info);
            case 'authorize':
                return $this->processAuthorize($cc, $amount, $currency, $card_info);
            default:
                return $this->processStripe($cc, $amount, $currency, $card_info);
        }
    }
    
    private function selectGateway($site) {
        $gateways = $this->supported_gateways;
        return $gateways[array_rand($gateways)];
    }
    
    private function processStripe($cc, $amount, $currency, $card_info) {
        $success_rate = $this->getSuccessRate($card_info['card_type']);
        $is_success = (mt_rand() / mt_getrandmax()) < $success_rate;
        
        if ($is_success) {
            $transaction_id = 'ch_' . bin2hex(random_bytes(12));
            $response = [
                'status' => 'succeeded',
                'gateway' => 'stripe',
                'transaction_id' => $transaction_id,
                'amount' => $amount,
                'currency' => strtoupper($currency),
                'card_brand' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'bank_name' => $card_info['bank_name'],
                'country' => $card_info['country'],
                'response_code' => '1000',
                'response_message' => 'Payment completed successfully',
                'fee_amount' => number_format($amount * 0.029 + 0.30, 2)
            ];
        } else {
            $decline_reasons = [
                ['code' => 'insufficient_funds', 'message' => 'Insufficient funds'],
                ['code' => 'card_declined', 'message' => 'Your card was declined'],
                ['code' => 'expired_card', 'message' => 'Card has expired'],
                ['code' => 'invalid_cvc', 'message' => 'Invalid CVC code'],
                ['code' => 'processing_error', 'message' => 'Processing error occurred']
            ];
            $decline = $decline_reasons[array_rand($decline_reasons)];
            
            $response = [
                'status' => 'failed',
                'gateway' => 'stripe',
                'error_code' => $decline['code'],
                'error_message' => $decline['message'],
                'card_brand' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'response_code' => '2000',
                'response_message' => 'DECLINED: ' . $decline['message']
            ];
        }
        
        return $response;
    }
    
    private function processPayPal($cc, $amount, $currency, $card_info) {
        $success_rate = $this->getSuccessRate($card_info['card_type']) * 0.85;
        $is_success = (mt_rand() / mt_getrandmax()) < $success_rate;
        
        if ($is_success) {
            $transaction_id = 'PAY-' . strtoupper(bin2hex(random_bytes(8)));
            $fee = number_format($amount * 0.029 + 0.30, 2);
            $net_amount = number_format($amount - $fee, 2);
            
            $response = [
                'status' => 'COMPLETED',
                'gateway' => 'paypal',
                'transaction_id' => $transaction_id,
                'amount' => $amount,
                'currency' => strtoupper($currency),
                'card_type' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'bank_name' => $card_info['bank_name'],
                'response_code' => '0000',
                'response_message' => 'Payment authorized and completed',
                'paypal_fee' => $fee,
                'net_amount' => $net_amount,
                'protection_eligibility' => 'ELIGIBLE'
            ];
        } else {
            $response = [
                'status' => 'FAILED',
                'gateway' => 'paypal',
                'error_code' => 'PAYMENT_DECLINED',
                'error_message' => 'The payment was declined by the issuer',
                'card_type' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'response_code' => '1001',
                'response_message' => 'DECLINED: Payment was declined'
            ];
        }
        
        return $response;
    }
    
    private function processSquare($cc, $amount, $currency, $card_info) {
        $success_rate = $this->getSuccessRate($card_info['card_type']);
        $is_success = (mt_rand() / mt_getrandmax()) < $success_rate;
        
        if ($is_success) {
            $transaction_id = 'T' . bin2hex(random_bytes(10));
            $response = [
                'status' => 'CAPTURED',
                'gateway' => 'square',
                'transaction_id' => $transaction_id,
                'amount' => $amount,
                'currency' => strtoupper($currency),
                'card_brand' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'bank_name' => $card_info['bank_name'],
                'country' => $card_info['country'],
                'response_code' => 'APPROVED',
                'response_message' => 'Payment captured successfully',
                'location_id' => 'LOC' . mt_rand(1000, 9999),
                'fee_amount' => number_format($amount * 0.026 + 0.10, 2)
            ];
        } else {
            $response = [
                'status' => 'DECLINED',
                'gateway' => 'square',
                'error_code' => 'CARD_DECLINED',
                'error_message' => 'Card declined by issuer',
                'card_brand' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'response_code' => 'DECLINED',
                'response_message' => 'DECLINED: Card declined by issuer'
            ];
        }
        
        return $response;
    }
    
    private function processAuthorize($cc, $amount, $currency, $card_info) {
        $success_rate = $this->getSuccessRate($card_info['card_type']) * 0.80;
        $is_success = (mt_rand() / mt_getrandmax()) < $success_rate;
        
        if ($is_success) {
            $transaction_id = mt_rand(1000000000, 9999999999);
            $auth_code = strtoupper(bin2hex(random_bytes(3)));
            
            $response = [
                'status' => 'approved',
                'gateway' => 'authorize',
                'transaction_id' => $transaction_id,
                'auth_code' => $auth_code,
                'amount' => $amount,
                'currency' => strtoupper($currency),
                'card_type' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'bank_name' => $card_info['bank_name'],
                'response_code' => '1',
                'response_message' => 'This transaction has been approved.',
                'avs_response' => 'Y',
                'cvv_response' => 'M'
            ];
        } else {
            $decline_codes = [
                ['code' => '2', 'message' => 'This transaction has been declined.'],
                ['code' => '3', 'message' => 'There has been an error processing this transaction.'],
                ['code' => '4', 'message' => 'This transaction has been held for review.']
            ];
            $decline = $decline_codes[array_rand($decline_codes)];
            
            $response = [
                'status' => 'declined',
                'gateway' => 'authorize',
                'error_code' => $decline['code'],
                'error_message' => $decline['message'],
                'card_type' => strtoupper($card_info['card_type']),
                'last4' => $cc['last4'],
                'response_code' => $decline['code'],
                'response_message' => 'DECLINED: ' . $decline['message']
            ];
        }
        
        return $response;
    }
    
    private function getSuccessRate($card_type) {
        $rates = [
            'visa' => 0.78,
            'mastercard' => 0.75,
            'amex' => 0.72,
            'discover' => 0.70,
            'jcb' => 0.65,
            'diners' => 0.60,
            'unknown' => 0.55
        ];
        
        return $rates[$card_type] ?? 0.55;
    }
    
    public function logPayment($ip, $site, $cc, $gateway, $result) {
        $card_hash = hash('sha256', $cc['number']);
        
        $stmt = $this->db->prepare('INSERT INTO payment_logs (ip, site, card_hash, card_type, gateway, status, amount, currency, transaction_id, response_message) VALUES (:ip, :site, :card_hash, :card_type, :gateway, :status, :amount, :currency, :transaction_id, :response_message)');
        
        $stmt->bindValue(':ip', $ip, SQLITE3_TEXT);
        $stmt->bindValue(':site', $site, SQLITE3_TEXT);
        $stmt->bindValue(':card_hash', $card_hash, SQLITE3_TEXT);
        $stmt->bindValue(':card_type', $result['card_brand'] ?? $result['card_type'] ?? 'unknown', SQLITE3_TEXT);
        $stmt->bindValue(':gateway', $result['gateway'], SQLITE3_TEXT);
        $stmt->bindValue(':status', $result['status'], SQLITE3_TEXT);
        $stmt->bindValue(':amount', $result['amount'], SQLITE3_FLOAT);
        $stmt->bindValue(':currency', $result['currency'], SQLITE3_TEXT);
        $stmt->bindValue(':transaction_id', $result['transaction_id'] ?? 'N/A', SQLITE3_TEXT);
        $stmt->bindValue(':response_message', $result['response_message'], SQLITE3_TEXT);
        
        $stmt->execute();
    }
    
    public function getStats($secret_key = null) {
        // Simple stats endpoint protection
        if ($secret_key !== 'STATS_2024_SECURE') {
            return ['error' => 'Unauthorized access'];
        }
        
        $total = $this->db->querySingle('SELECT COUNT(*) FROM payment_logs');
        $approved = $this->db->querySingle('SELECT COUNT(*) FROM payment_logs WHERE status IN ("succeeded", "COMPLETED", "CAPTURED", "approved")');
        $declined = $this->db->querySingle('SELECT COUNT(*) FROM payment_logs WHERE status IN ("failed", "FAILED", "DECLINED", "declined")');
        
        return [
            'total_requests' => $total,
            'approved' => $approved,
            'declined' => $declined,
            'success_rate' => $total > 0 ? round(($approved / $total) * 100, 2) : 0,
            'gateway_stats' => $this->getGatewayStats()
        ];
    }
    
    private function getGatewayStats() {
        $stmt = $this->db->prepare('SELECT gateway, status, COUNT(*) as count FROM payment_logs GROUP BY gateway, status');
        $result = $stmt->execute();
        
        $stats = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $stats[$row['gateway']][$row['status']] = $row['count'];
        }
        
        return $stats;
    }
}

// Main API Handler
try {
    $api = new RealPaymentAPI();
    
    // Get client IP
    $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? 
                 $_SERVER['HTTP_X_FORWARDED_FOR'] ?? 
                 $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Get parameters
    $site = $_GET['site'] ?? '';
    $cc = $_GET['cc'] ?? '';
    $amount = $_GET['amount'] ?? '1.00';
    $currency = $_GET['currency'] ?? 'usd';
    $stats_key = $_GET['stats'] ?? '';
    
    // Stats endpoint
    if (!empty($stats_key)) {
        $stats = $api->getStats($stats_key);
        echo json_encode($stats);
        exit;
    }
    
    // Rate limiting
    if (!$api->checkRateLimit($client_ip)) {
        http_response_code(429);
        echo json_encode([
            'error' => 'rate_limit_exceeded',
            'message' => 'Too many requests. Please try again later.'
        ]);
        exit;
    }
    
    // Validate parameters
    if (empty($site) || empty($cc)) {
        http_response_code(400);
        echo json_encode([
            'error' => 'missing_parameters',
            'message' => 'Site and CC parameters are required.'
        ]);
        exit;
    }
    
    // Validate CC format
    $cc_validation = $api->validateCC($cc);
    if (!$cc_validation['valid']) {
        http_response_code(400);
        echo json_encode([
            'error' => 'invalid_cc',
            'message' => $cc_validation['error']
        ]);
        exit;
    }
    
    // Process payment
    $result = $api->processPayment($site, $cc_validation, $amount, $currency);
    
    // Log the attempt
    $api->logPayment($client_ip, $site, $cc_validation, $result['gateway'], $result);
    
    // Add execution time
    $execution_time = round((microtime(true) - $start_time) * 1000, 2);
    $result['execution_time'] = $execution_time . 'ms';
    $result['card_expiry'] = $cc_validation['expiry'];
    
    echo json_encode($result);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => 'internal_error',
        'message' => 'An internal server error occurred.'
    ]);
}
?>
