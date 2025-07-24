/*
 * ===== SmartInject Injection Details =====
 * Function      : subscribeToService
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. The exploit requires: 1) First transaction: User subscribes to a service with subscribeToService(), setting up subscription state including expiry time based on 'now' timestamp. 2) Second transaction: User calls cancelSubscription() at a strategic time to exploit timestamp manipulation. A miner can manipulate the timestamp in the cancelSubscription() transaction to maximize the refund calculation, making it appear that more time remains on the subscription than actually does. The vulnerability persists in state variables (subscriptionExpiry, subscriptionAmount, activeSubscriptions) between transactions and requires multiple calls to exploit.
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
    address public constant storeAccountAddress = 0x017A759A2095841122b4b4e90e40AE579a4361f1;
    address public constant cloudAccountAddress = 0x38C6Ec7331ce04891154b953a79B157703CaE38a;
    
    using SafeMath for uint256;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables must be declared at contract scope
    mapping(address => uint256) subscriptionExpiry;
    mapping(address => uint256) subscriptionAmount;
    mapping(address => bool) activeSubscriptions;
    
    event SubscriptionCreated(address indexed subscriber, uint256 amount, uint256 expiry);
    event SubscriptionRenewed(address indexed subscriber, uint256 newExpiry);
    event SubscriptionCanceled(address indexed subscriber, uint256 refundAmount);
    
    constructor() public {
        totalSupply_ = 21000000000000000000000000;
        balances[msg.sender] = 21000000000000000000000000;
    }

    function subscribeToService(uint256 numTokens, uint256 durationInSeconds) public returns (bool) {
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        require(durationInSeconds > 0);
        
        uint256 expiryTime = now + durationInSeconds;
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[hostingAccountAddress] = balances[hostingAccountAddress].add(numTokens);
        
        subscriptionExpiry[msg.sender] = expiryTime;
        subscriptionAmount[msg.sender] = numTokens;
        activeSubscriptions[msg.sender] = true;
        
        emit SubscriptionCreated(msg.sender, numTokens, expiryTime);
        return true;
    }
    
    function cancelSubscription() public returns (bool) {
        require(activeSubscriptions[msg.sender]);
        
        uint256 currentTime = now;
        uint256 expiry = subscriptionExpiry[msg.sender];
        
        if (currentTime < expiry) {
            // Calculate refund based on remaining time - vulnerable to timestamp manipulation
            uint256 totalDuration = expiry - (expiry - subscriptionAmount[msg.sender]);
            uint256 remainingTime = expiry - currentTime;
            uint256 refundAmount = (subscriptionAmount[msg.sender] * remainingTime) / totalDuration;
            
            balances[hostingAccountAddress] = balances[hostingAccountAddress].sub(refundAmount);
            balances[msg.sender] = balances[msg.sender].add(refundAmount);
            
            emit SubscriptionCanceled(msg.sender, refundAmount);
        }
        
        activeSubscriptions[msg.sender] = false;
        subscriptionExpiry[msg.sender] = 0;
        subscriptionAmount[msg.sender] = 0;
        
        return true;
    }
    
    function isSubscriptionActive(address subscriber) public view returns (bool) {
        return activeSubscriptions[subscriber] && now < subscriptionExpiry[subscriber];
    }
    // === END FALLBACK INJECTION ===

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
    
    
    function payForStore(uint numTokens) public returns (bool){
        
        require(numTokens <= balances[msg.sender]);
        require(numTokens > 0);
        
        balances[msg.sender] = balances[msg.sender].sub(numTokens);
        balances[storeAccountAddress] = balances[storeAccountAddress].add(numTokens);
        emit StorePayment(msg.sender, numTokens);
        return true;
    }
    
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
}
