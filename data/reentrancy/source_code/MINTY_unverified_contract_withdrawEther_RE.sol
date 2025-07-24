/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEther
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Code Changes Made:**
 *    - Added local variable `withdrawAmount` to capture the current `ownerBalance`
 *    - Added conditional check `if (withdrawAmount > 0)` to make the vulnerability more realistic
 *    - Maintained the vulnerable pattern of external call before state update
 *    - Preserved the function's core logic and signature
 * 
 * 2. **Multi-Transaction Exploitation Process:**
 *    
 *    **Phase 1 - State Accumulation (Multiple Transactions):**
 *    - Attacker needs to first accumulate `ownerBalance` through multiple calls to the fallback function
 *    - Each call to the fallback function (with correct fee) increases `ownerBalance` by the fee amount
 *    - This requires multiple transactions over time to build up a significant balance worth attacking
 *    
 *    **Phase 2 - Reentrancy Setup (Single Transaction):**
 *    - Attacker deploys a malicious contract that becomes the new owner (if they can exploit `transferOwnership`)
 *    - Or they wait until they legitimately become the owner through some other mechanism
 *    
 *    **Phase 3 - Exploitation (Multi-Transaction Reentrancy):**
 *    - When `withdrawEther()` is called, the `owner.transfer(withdrawAmount)` triggers the attacker's fallback function
 *    - During reentrancy, `ownerBalance` is still non-zero (hasn't been reset yet)
 *    - The attacker can call `withdrawEther()` again, withdrawing the same amount multiple times
 *    - Each reentrant call sees the same `ownerBalance` value until the original call completes
 * 
 * 3. **Why Multiple Transactions Are Required:**
 *    - **State Accumulation**: The vulnerability requires `ownerBalance` to have accumulated value from previous transactions through the fallback function
 *    - **Setup Phase**: The attacker needs to become the owner through separate transactions
 *    - **Exploitation Timing**: The reentrancy exploits the window between the external call and state update, but only after sufficient balance has accumulated
 *    - **Economic Viability**: The attack is only profitable if enough value has been accumulated through multiple prior transactions
 * 
 * 4. **Stateful Dependencies:**
 *    - The vulnerability depends on the persistent state of `ownerBalance` that grows over multiple transactions
 *    - The exploit's success is directly proportional to how much value was accumulated in previous transactions
 *    - The vulnerability cannot be exploited in a single transaction from a clean state - it requires the contract to have accumulated fees over time
 * 
 * This creates a realistic vulnerability pattern where the contract must be operational and accumulating fees over multiple transactions before the reentrancy becomes exploitable, making it a true stateful, multi-transaction vulnerability.
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
    function MINTY() public {
        owner = msg.sender;
        balanceOf[owner] = minted;
        balanceOf[this] = totalSupply - balanceOf[owner];
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint256 withdrawAmount = ownerBalance;
        if (withdrawAmount > 0) {
            // External call before state update - creates reentrancy window
            owner.transfer(withdrawAmount);
            // State update after external call
            ownerBalance = 0;
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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