/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the spender contract after the allowance has been set. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the spender contract using `_spender.call()` after the allowance state has been updated
 * 2. The call uses `onApprovalReceived` as a notification mechanism, which appears legitimate
 * 3. The external call occurs after the `allowed` mapping has been modified and the `Approval` event has been emitted
 * 4. Added a code length check to only call contracts (not EOAs)
 * 
 * **Multi-Transaction Exploitation Flow:**
 * 1. **Transaction 1**: User calls `approve(maliciousContract, 1000)` 
 *    - `allowed[user][maliciousContract] = 1000` is set
 *    - External call to `maliciousContract.onApprovalReceived()` is made
 *    - Malicious contract can now reenter and call `transferFrom(user, attacker, 1000)` using the newly set allowance
 *    - This transfers 1000 tokens to the attacker
 * 
 * 2. **Transaction 2**: The original approve call completes, but the allowance was already consumed
 *    - The user believes they approved 1000 tokens for legitimate use
 *    - But the tokens were already stolen during the reentrancy
 * 
 * 3. **Transaction 3**: When the legitimate spender tries to use the allowance later, it fails because the allowance was already consumed by the attacker
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the allowance state to be set first (in the approve function)
 * - Then the malicious contract needs to use that allowance via `transferFrom` (which is a separate function call)
 * - The exploit cannot happen in a single transaction because it requires the allowance to be set before it can be used
 * - The state change (`allowed` mapping) persists between transactions, enabling the attack
 * - The vulnerability requires interaction between the approve function and the transferFrom function across multiple transactions
 * 
 * **Stateful Nature:**
 * - The `allowed` mapping maintains state between transactions
 * - The vulnerability exploits this persistent state by manipulating the allowance during the approval process
 * - The attack works because the allowance state is consumed in a different transaction than where it was set
 * 
 * This creates a realistic time-of-check-time-of-use (TOCTOU) vulnerability where the allowance can be manipulated between being set and being used legitimately.
 */
pragma solidity ^0.4.17;

library SafeMathMod {// Partial SafeMath Library

    function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
        require((c = a - b) < a);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        require((c = a + b) > a);
        return c;
    }
}

contract Paymec {//is inherently ERC20
    using SafeMathMod for uint256;

    /**
    * @constant name The name of the token
    * @constant symbol  The symbol used to display the currency
    * @constant decimals  The number of decimals used to dispay a balance
    * @constant totalSupply The total number of tokens times 10^ of the number of decimals
    * @constant MAX_UINT256 Magic number for unlimited allowance
    * @storage balanceOf Holds the balances of all token holders
    * @storage allowed Holds the allowable balance to be transferable by another address.
    */

    string constant public name = "Paymec";

    string constant public symbol = "PMC";

    uint8 constant public decimals = 8;

    uint256 constant public totalSupply = 100000000e8;

    uint256 constant private MAX_UINT256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);

    event TransferFrom(address indexed _spender, address indexed _from, address indexed _to, uint256 _value);

    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    constructor() public {balanceOf[msg.sender] = totalSupply;}

    /**
    * @notice send `_value` token to `_to` from `msg.sender`
    *
    * @param _to The address of the recipient
    * @param _value The amount of token to be transferred
    * @return Whether the transfer was successful or not
    */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        /* Ensures that tokens are not sent to address "0x0" */
        require(_to != address(0));
        /* Prevents sending tokens directly to contracts. */
        require(isNotContract(_to));

        /* SafeMathMOd.sub will throw if there is not enough balance and if the transfer value is 0. */
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
    * @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
    *
    * @param _from The address of the sender
    * @param _to The address of the recipient
    * @param _value The amount of token to be transferred
    * @return Whether the transfer was successful or not
    */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        /* Ensures that tokens are not sent to address "0x0" */
        require(_to != address(0));
        /* Ensures tokens are not sent to this contract */
        require(_to != address(this));
        
        uint256 allowance = allowed[_from][msg.sender];
        /* Ensures sender has enough available allowance OR sender is balance holder allowing single transsaction send to contracts*/
        require(_value <= allowance || _from == msg.sender);

        /* Use SafeMathMod to add and subtract from the _to and _from addresses respectively. Prevents under/overflow and 0 transfers */
        balanceOf[_to] = balanceOf[_to].add(_value);
        balanceOf[_from] = balanceOf[_from].sub(_value);

        /* Only reduce allowance if not MAX_UINT256 in order to save gas on unlimited allowance */
        /* Balance holder does not need allowance to send from self. */
        if (allowed[_from][msg.sender] != MAX_UINT256 && _from != msg.sender) {
            allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        }
        emit Transfer(_from, _to, _value);
        return true;
    }

    /**
    * @dev Transfer the specified amounts of tokens to the specified addresses.
    * @dev Be aware that there is no check for duplicate recipients.
    *
    * @param _toAddresses Receiver addresses.
    * @param _amounts Amounts of tokens that will be transferred.
    */
    function multiPartyTransfer(address[] _toAddresses, uint256[] _amounts) public {
        /* Ensures _toAddresses array is less than or equal to 255 */
        require(_toAddresses.length <= 255);
        /* Ensures _toAddress and _amounts have the same number of entries. */
        require(_toAddresses.length == _amounts.length);

        for (uint8 i = 0; i < _toAddresses.length; i++) {
            transfer(_toAddresses[i], _amounts[i]);
        }
    }

    /**
    * @dev Transfer the specified amounts of tokens to the specified addresses from authorized balance of sender.
    * @dev Be aware that there is no check for duplicate recipients.
    *
    * @param _from The address of the sender
    * @param _toAddresses The addresses of the recipients (MAX 255)
    * @param _amounts The amounts of tokens to be transferred
    */
    function multiPartyTransferFrom(address _from, address[] _toAddresses, uint256[] _amounts) public {
        /* Ensures _toAddresses array is less than or equal to 255 */
        require(_toAddresses.length <= 255);
        /* Ensures _toAddress and _amounts have the same number of entries. */
        require(_toAddresses.length == _amounts.length);

        for (uint8 i = 0; i < _toAddresses.length; i++) {
            transferFrom(_from, _toAddresses[i], _amounts[i]);
        }
    }

    /**
    * @notice `msg.sender` approves `_spender` to spend `_value` tokens
    *
    * @param _spender The address of the account able to transfer the tokens
    * @param _value The amount of tokens to be approved for transfer
    * @return Whether the approval was successful or not
    */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        /* Ensures address "0x0" is not assigned allowance. */
        require(_spender != address(0));

        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify spender contract about the approval
        uint256 size;
        assembly { size := extcodesize(_spender) }
        if (size > 0) {
            _spender.call(
                abi.encodeWithSignature("onApprovalReceived(address,uint256)", msg.sender, _value)
            );
            // Continue execution even if notification fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    /**
    * @param _owner The address of the account owning tokens
    * @param _spender The address of the account able to transfer the tokens
    * @return Amount of remaining tokens allowed to spent
    */
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        remaining = allowed[_owner][_spender];
    }

    function isNotContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
        /* retrieve the size of the code on target address, this needs assembly */
        length := extcodesize(_addr)
        }
        return (length == 0);
    }

    // revert on eth transfers to this contract
    function() public payable {revert();}
}
