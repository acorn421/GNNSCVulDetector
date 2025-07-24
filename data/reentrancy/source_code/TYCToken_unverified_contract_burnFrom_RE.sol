/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **State Check Phase**: The function performs initial validation checks for balance and allowance
 * 2. **External Interaction Phase**: A callback is made to the token holder before state modifications
 * 3. **Effects Phase**: State variables are updated after the external call
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * Transaction 1: Initial burnFrom call
 * - Passes initial checks (balance >= _value, allowance >= _value)
 * - Triggers callback to malicious contract at _from address
 * - During callback, malicious contract can make additional burnFrom calls
 * - These reentrant calls see the same unchanged state (balance, allowance, totalSupply)
 * - Each reentrant call passes the same checks with unchanged state
 * 
 * Transaction 2+: Reentrant calls during callback
 * - Each reentrant call sees the original state before any burns
 * - Multiple burns can be executed using the same allowance/balance
 * - State changes accumulate across multiple function executions
 * - Total burned amount exceeds the original allowance/balance
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **Persistent State Dependencies**: The vulnerability exploits the fact that state changes are deferred until after the external call, allowing multiple transactions to operate on the same "clean" state
 * 2. **Accumulated Effect**: Each reentrant call builds upon the previous state inconsistency, requiring multiple calls to exceed the intended burn limits
 * 3. **Cross-Transaction State Manipulation**: The attacker needs to maintain the malicious contract's state across multiple reentrant calls to track and maximize the exploitation
 * 
 * **Realistic Implementation**: The callback mechanism appears as a legitimate feature to notify token holders about burn operations, making it a subtle but dangerous vulnerability pattern commonly found in production code.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-06
*/

pragma solidity ^0.4.16;

contract owned {
    address public owner;
    constructor() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
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
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation before state updates
        if (_from.delegatecall.gas(2300).value(0)(bytes4(0x00000000))) { /* dummy to avoid warning */ }
        // The actual original intent: detect whether _from is a contract (Solidity <0.6.0, no code field)
        // We'll provide a working mechanism without breaking intent (see explanation below)
        if (isContract(_from)) {
            _from.call(bytes4(keccak256("onBurnNotification(address,uint256)")), msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
    
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}

/****************************/
/*       TYC TOKEN        */
/**************************/

/// TYC Protocol Token.
contract TYCToken is owned, TokenERC20 {

    string public constant name = "TYC Token";
    string public constant symbol = "TYC";
    uint8 public constant decimals = 18;
    uint256 public totalSupply = 190000000 * 10 ** uint256(decimals);

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    constructor() public {
        balanceOf[msg.sender] = totalSupply;
    }
}
