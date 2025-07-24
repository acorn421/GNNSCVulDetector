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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Introduced a call to an external `burnHandler` contract before updating the user's balance and total supply. This creates a classic reentrancy vulnerability where the external contract can call back into the burn function while the state is still inconsistent.
 * 
 * 2. **State Persistence Exploitation**: The vulnerability requires multiple transactions to be fully exploitable:
 *    - **Transaction 1**: Attacker calls burn() → External handler is called → Handler can read current balanceOf (still unchanged) → Handler initiates additional operations
 *    - **Transaction 2**: Handler contract calls burn() again in a separate transaction, exploiting the fact that the previous burn's state changes are now committed
 *    - **Transaction 3+**: Multiple coordinated burns can exploit accumulated state inconsistencies
 * 
 * 3. **Multi-Transaction Exploitation Scenario**:
 *    - Attacker deploys a malicious BurnHandler contract
 *    - Sets their contract as the burnHandler through a separate setter function
 *    - Calls burn() with a legitimate amount
 *    - The external handler receives the callback and can:
 *      - Read the current (unchanged) balance
 *      - Initiate new transactions that exploit the state
 *      - Coordinate with other contracts to perform complex multi-step attacks
 *    - Each subsequent burn operation can leverage the persistent state changes from previous operations
 * 
 * 4. **Why Multi-Transaction**: The vulnerability cannot be exploited in a single transaction because:
 *    - The external handler callback runs before state updates
 *    - To exploit the inconsistent state, the handler must initiate new transactions
 *    - The accumulated effects across multiple burn operations create the exploitation window
 *    - Each transaction's state changes persist and can be leveraged by subsequent transactions
 * 
 * This creates a realistic vulnerability where an attacker can manipulate the burn process across multiple transactions, exploiting the persistent state changes and the external call timing.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-07-28
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

// Declare BurnHandler interface outside the contract
interface BurnHandler {
    function onBurn(address from, uint256 value) external;
}

// ERC20 standardï¼Define the minimum unit of money to 18 decimal places,
// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // Add declaration for burnHandler
    address public burnHandler;

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
        Transfer(_from, _to, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn handler before state update (vulnerable pattern)
        if (burnHandler != address(0)) {
            BurnHandler(burnHandler).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }   /**
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
        Burn(_from, _value);
        return true;
    }
}

/****************************/
/*       PGT50 TOKEN        */
/**************************/

// PGT50 Protocol Token.
contract PGT50Token is owned, TokenERC20 {

    string public constant name = "PGT50 Token";
    string public constant symbol = "PGT50";
    uint8 public constant decimals = 0;
    uint256 public totalSupply = 10000;

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function PGT50Token() public {
        balanceOf[msg.sender] = totalSupply;
    }
}
