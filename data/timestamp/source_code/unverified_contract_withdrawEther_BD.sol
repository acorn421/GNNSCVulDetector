/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires:
 * 
 * **State Changes Required:**
 * - First transaction: Sets `withdrawalRequestTime` and returns early
 * - Subsequent transactions: Checks multiple timestamp-based conditions
 * 
 * **Specific Timestamp Dependence Vulnerabilities:**
 * 1. **Time-based withdrawal delay**: Uses `block.timestamp` without proper validation for critical timing logic
 * 2. **Daily withdrawal window**: Relies on `block.timestamp % 86400` for access control
 * 3. **Block number as time proxy**: Uses `block.number` differences to calculate withdrawal limits
 * 4. **Stored block properties**: Stores timestamp and block number in state for later critical operations
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Owner calls `withdrawEther()` → Sets withdrawal request timestamp, no funds transferred
 * - **Transaction 2+**: Owner calls `withdrawEther()` again → Processes withdrawal based on manipulable timestamp conditions
 * 
 * **Vulnerability Exploitation:**
 * - Miners can manipulate `block.timestamp` within consensus limits (±15 seconds)
 * - Miners can delay block inclusion to affect withdrawal timing
 * - The daily window check (`block.timestamp % 86400`) can be manipulated by timestamp adjustment
 * - Block number timing calculations can be manipulated through block reordering
 * - State persistence between transactions enables accumulated exploitation potential
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state setup (withdrawal request) in one transaction
 * - Actual exploitation occurs in subsequent transactions when timestamp conditions are evaluated
 * - The time-based limits and windows only become exploitable after the initial state is set
 * - Cannot be exploited atomically within a single transaction due to the early return mechanism
 */
pragma solidity ^0.4.19;

contract MINTY {
    string public name = 'MINTY';
    string public symbol = 'MINTY';
    uint8 public decimals = 18;
    uint public totalSupply = 10000000000000000000000000;
    uint public minted = totalSupply / 5;
    uint public minReward = 1000000000000000000;
    uint public fee = 700000000000000;
    uint public reducer = 1000;
    uint private randomNumber;
    address public owner;
    uint private ownerBalance;
    
    /* Newly declared variables for withdrawal logic */
    uint public withdrawalRequestTime;
    uint public withdrawalDelay = 1 days; // Arbitrary default value, can be set externally
    uint public withdrawalWindow = 3600; // 1 hour window default
    uint public withdrawalRequestBlock;
    uint public lastWithdrawalTimestamp;
    uint public lastWithdrawalBlock;
    
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public successesOf;
    mapping (address => uint256) public failsOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
    
    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public {
        owner = msg.sender;
        balanceOf[owner] = minted;
        balanceOf[this] = totalSupply - balanceOf[owner];
        // Initialize withdrawalRequestTime and related vars
        withdrawalRequestTime = 0;
        withdrawalRequestBlock = 0;
        lastWithdrawalTimestamp = 0;
        lastWithdrawalBlock = 0;
    }
    
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) external {
        _transfer(msg.sender, _to, _value);
    }
    
    /* Transfer tokens from other address */
    function transferFrom(address _from, address _to, uint256 _value) external returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    /* Set allowance for other address */
    function approve(address _spender, uint256 _value) external returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function withdrawEther() external onlyOwner {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        if (withdrawalRequestTime == 0) {
            // First transaction: Set withdrawal request with current timestamp
            withdrawalRequestTime = block.timestamp;
            return;
        }
        
        // Subsequent transactions: Process withdrawal based on time conditions
        require(block.timestamp >= withdrawalRequestTime + withdrawalDelay, "Withdrawal delay not met");
        require(block.timestamp % 86400 < withdrawalWindow, "Not within daily withdrawal window");
        
        // Additional timestamp-based validation using block.number as time proxy
        uint timeBasedLimit = (block.number - withdrawalRequestBlock) * 1 ether;
        require(ownerBalance <= timeBasedLimit, "Withdrawal amount exceeds time-based limit");
        
        // Store block properties for critical operation
        lastWithdrawalTimestamp = block.timestamp;
        lastWithdrawalBlock = block.number;
        withdrawalRequestBlock = block.number;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        owner.transfer(ownerBalance);
        ownerBalance = 0;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        withdrawalRequestTime = 0; // Reset for next withdrawal cycle
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function () external payable {
        if (msg.value == fee) {
            randomNumber += block.timestamp + uint(msg.sender);
            uint minedAtBlock = uint(block.blockhash(block.number - 1));
            uint minedHashRel = uint(sha256(minedAtBlock + randomNumber + uint(msg.sender))) % 10000000;
            uint balanceRel = balanceOf[msg.sender] * 1000 / minted;
            if (balanceRel >= 1) {
                if (balanceRel > 255) {
                    balanceRel = 255;
                }
                balanceRel = 2 ** balanceRel;
                balanceRel = 5000000 / balanceRel;
                balanceRel = 5000000 - balanceRel;
                if (minedHashRel < balanceRel) {
                    uint reward = minReward + minedHashRel * 1000 / reducer * 100000000000000;
                    _transfer(this, msg.sender, reward);
                    minted += reward;
                    successesOf[msg.sender]++;
                } else {
                    Transfer(this, msg.sender, 0);
                    failsOf[msg.sender]++;
                }
                ownerBalance += fee;
                reducer++;
            } else {
                revert();
            }
        } else {
            revert();
        }
    }
}
