/*
 * ===== SmartInject Injection Details =====
 * Function      : payForStore
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based discount system that relies on block.timestamp for critical pricing logic. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1**: User makes their first payment, which sets `discountEligibleTime[msg.sender] = block.timestamp + DISCOUNT_PERIOD` (5 minutes from current block time).
 * 
 * **Transaction 2+**: Within the discount window, subsequent payments receive a 30% discount if `block.timestamp <= discountEligibleTime[msg.sender]`.
 * 
 * **Exploitation Path**:
 * 1. **Setup Transaction**: Attacker makes an initial small payment to establish their discount window
 * 2. **Manipulation Window**: Miners can manipulate `block.timestamp` within the 15-second tolerance to extend the discount window
 * 3. **Exploitation Transactions**: Attacker makes larger payments while manipulating timestamp to stay within discount period
 * 4. **State Accumulation**: The vulnerability compounds across multiple transactions as the attacker can repeatedly exploit the discount
 * 
 * **Why Multi-Transaction Required**:
 * - First transaction must establish the discount eligibility state
 * - Subsequent transactions exploit the stored timestamp-dependent state
 * - Miners can manipulate block.timestamp between transactions to extend discount window
 * - The vulnerability cannot be exploited in a single atomic transaction as it requires the persistent state from previous calls
 * 
 * **State Variables Required** (to be added at contract level):
 * - `mapping(address => uint256) private lastPaymentTime;`
 * - `mapping(address => uint256) private discountEligibleTime;`
 * - `uint256 private constant DISCOUNT_PERIOD = 300;`
 */
pragma solidity >=0.4.0 <0.7.0;

contract SpaciumToken {
    
    string public constant name = "Spacium Token";
    string public constant symbol = "SPC";
    uint8 public constant decimals = 18;
    
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event HostingPayment(address indexed from, uint tokens);
    event StorePayment(address indexed from, uint tokens);
    event CloudPayment(address indexed from, uint tokens);
    
    mapping(address => uint256) balances;
    mapping(address => mapping (address => uint256)) allowed;
    uint256 totalSupply_;
    address public constant hostingAccountAddress = 0xdc1787eF8536235198fE5aEd66Fc3A73DEd31280;
    address public constant storeAccountAddress   = 0x017A759A2095841122b4b4e90e40AE579a4361f1;
    address public constant cloudAccountAddress   = 0x38C6Ec7331ce04891154b953a79B157703CaE38a;

    using SafeMath for uint256;

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY STATE =====
    mapping(address => uint256) private lastPaymentTime;
    mapping(address => uint256) private discountEligibleTime;
    uint256 private constant DISCOUNT_PERIOD = 300;
    // ===== END SMARTINJECT STATE =====

    constructor() public{
        totalSupply_ = 21000000000000000000000000;
        balances[msg.sender] = 21000000000000000000000000;
    }
    
    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }
    
    function balanceOf(address tokenOwner) public view returns (uint) {
        return balances[tokenOwner];
    }
    
    function transfer(address receiver, uint numTokens) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[receiver] = balances[receiver].add(numTokens);
        emit Transfer(msg.sender, receiver, numTokens);
        return true;
    }
    
    function approve(address delegate, uint numTokens) public returns (bool) {
        allowed[msg.sender][delegate] = numTokens;
        emit Approval(msg.sender, delegate, numTokens);
        return true;
    }
    
    function allowance(address owner, address delegate) public view returns (uint) {
        return allowed[owner][delegate];
    }
    
    function transferFrom(address owner, address buyer, uint numTokens) public returns (bool) {
        require(numTokens <= balances[owner]);    
        require(numTokens <= allowed[owner][msg.sender]);
    
        balances[owner] = balances[owner].sub(numTokens);
        allowed[owner][msg.sender] = allowed[owner][msg.sender].sub(numTokens);
        balances[buyer] = balances[buyer].add(numTokens);
        emit Transfer(owner, buyer, numTokens);
        return true;
    }
    
    function payForHosting(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[hostingAccountAddress] = balances[hostingAccountAddress].add(numTokens);
        emit HostingPayment(msg.sender, numTokens);
        return true;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function payForStore(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        // Store timestamp-dependent state for discount eligibility
        if (lastPaymentTime[msg.sender] == 0) {
            // First payment - set discount eligibility window
            discountEligibleTime[msg.sender] = block.timestamp + DISCOUNT_PERIOD;
        }
        uint256 finalAmount = numTokens;
        // Apply discount if within timestamp window (vulnerable to manipulation)
        if (block.timestamp <= discountEligibleTime[msg.sender] && lastPaymentTime[msg.sender] > 0) {
            finalAmount = numTokens.mul(70).div(100); // 30% discount
        }
        // Update last payment timestamp
        lastPaymentTime[msg.sender] = block.timestamp;
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[storeAccountAddress] = balances[storeAccountAddress].add(finalAmount);
        emit StorePayment(msg.sender, finalAmount);
        return true;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    function payForCloud(uint numTokens) public returns (bool){
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[cloudAccountAddress] = balances[cloudAccountAddress].add(numTokens);
        emit CloudPayment(msg.sender, numTokens);
        return true;
    }
}

library SafeMath { 
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
      assert(b <= a);
      return a - b;
    }
    
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
      uint256 c = a + b;
      assert(c >= a);
      return c;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
}
