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
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: 
 *    - `mapping(address => address) public burnCallbacks` - allows users to register callback contracts
 *    - `uint256 public pendingBurns` - tracks burns in progress, creating persistent state
 * 
 * 2. **Added setBurnCallback Function**: 
 *    - Allows users to register a callback contract that will be notified during burns
 *    - This is a realistic feature for DeFi integration
 * 
 * 3. **Modified burn Function Flow**:
 *    - Added `pendingBurns += _value` before external call
 *    - Added external call to user-controlled callback using existing `tokenRecipient` interface
 *    - Moved critical state updates (`balanceOf` and `totalSupply`) AFTER the external call
 *    - Added `pendingBurns -= _value` after state updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup:**
 * - Attacker deploys a malicious contract implementing `tokenRecipient`
 * - Attacker calls `setBurnCallback(maliciousContract)` to register callback
 * - Attacker acquires tokens to burn
 * 
 * **Transaction 2 - Initial Burn:**
 * - Attacker calls `burn(100)` 
 * - Function checks `balanceOf[attacker] >= 100` ✓
 * - `pendingBurns` increases by 100
 * - External call to malicious callback occurs
 * - Malicious callback can observe `pendingBurns` state and that balance hasn't been deducted yet
 * 
 * **Transaction 3 - Reentrant Exploit:**
 * - Malicious callback calls `burn(100)` again in same transaction
 * - Balance check still passes because previous burn hasn't updated `balanceOf` yet
 * - `pendingBurns` increases to 200
 * - Second external call can potentially call back again
 * - Eventually state updates occur, but `totalSupply` is reduced by more than the actual tokens burned
 * 
 * **Why Multi-Transaction Required:**
 * 
 * 1. **State Accumulation**: The `pendingBurns` variable accumulates state across calls, creating inconsistency windows
 * 2. **Callback Registration**: Requires separate transaction to set up malicious callback
 * 3. **Reentrancy Chain**: Each reentrant call builds on the state changes from previous calls
 * 4. **Persistent State Corruption**: The vulnerability creates lasting state inconsistencies that persist between transactions
 * 
 * **Exploitation Impact:**
 * - `totalSupply` can be reduced by more than actual tokens burned
 * - `pendingBurns` can become inconsistent with actual pending operations
 * - Multiple users can exploit this simultaneously across different transaction sequences
 * - The vulnerability compounds over multiple burn operations
 */
/**
 *Submitted for verification at Etherscan.io on 2019-11-06
*/

pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => address) public burnCallbacks;
    uint256 public pendingBurns;
    
    function setBurnCallback(address _callback) public {
        burnCallbacks[msg.sender] = _callback;
    }
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        
        // Mark burn as pending before external call
        pendingBurns += _value;
        
        // External call to user-controlled callback before state updates
        if (burnCallbacks[msg.sender] != address(0)) {
            tokenRecipient(burnCallbacks[msg.sender]).receiveApproval(msg.sender, _value, this, "burn");
        }
        
        // State updates occur after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        pendingBurns -= _value;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
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
    function TYCToken() public {
        balanceOf[msg.sender] = totalSupply;
    }
}
