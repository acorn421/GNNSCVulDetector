/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pendingBurns mapping to track accumulated burn amounts across transactions and an external call to a reward contract before state updates. The vulnerability requires multiple transactions to build up pendingBurns state and can be exploited through reentrancy during the reward calculation callback.
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingBurns` mapping to track accumulated burn amounts across transactions
 * 2. Added `burnRewardContract` address for external reward calculations
 * 3. Inserted external call to `calculateReward()` after balance check but before state updates
 * 4. The `pendingBurns[msg.sender] += _value` creates persistent state that accumulates across transactions
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Phase**: Attacker deploys malicious contract implementing IBurnReward interface
 * 2. **Accumulation Phase**: Attacker makes multiple small burn calls to build up pendingBurns state
 * 3. **Exploitation Phase**: During the external call to calculateReward(), the malicious contract re-enters burn() multiple times
 * 4. **State Corruption**: Each re-entry passes the balance check (using original balance) but only final state update takes effect, allowing burning more tokens than owned
 * 
 * **Why Multiple Transactions Are Required:**
 * - The pendingBurns state must be built up across multiple transactions to create significant accumulated value
 * - The vulnerability exploits the accumulated state from previous transactions during the reentrancy
 * - A single transaction cannot build sufficient pendingBurns state to make the exploit profitable
 * - The attack requires coordination between the accumulated state and the reentrancy callback
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnReward {
    function calculateReward(address user, uint256 pendingBurn) external;
}

contract Supershop {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address with allowance
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy  own tokens
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variable to track pending burns for reward calculations
    mapping(address => uint256) public pendingBurns;
    address public burnRewardContract;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        
        // Track accumulated burns across transactions
        pendingBurns[msg.sender] += _value;
        
        // External call to reward contract before state updates - VULNERABLE!
        if (burnRewardContract != address(0)) {
            // This external call can re-enter before balance updates
            IBurnReward(burnRewardContract).calculateReward(msg.sender, pendingBurns[msg.sender]);
        }
        
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                              // Update totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account with allowance
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
