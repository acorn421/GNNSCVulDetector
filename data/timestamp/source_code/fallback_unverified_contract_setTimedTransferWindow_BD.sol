/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimedTransferWindow
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a timed transfer system that relies on block.timestamp for precise timing control. The vulnerability is stateful and requires multiple transactions: 1) First transaction calls setTimedTransferWindow() to schedule a transfer and lock tokens, 2) Second transaction calls executeTimedTransfer() within the time window. The vulnerability allows miners to manipulate block.timestamp within certain bounds to either extend or reduce the transfer window, potentially allowing transfers to be executed outside their intended timeframe or preventing legitimate transfers from being executed. The state persists between transactions through the mapping variables that track active transfers, amounts, recipients, and window end times.
 */
pragma solidity ^0.4.17;

library SafeMathMod {// Partial SafeMath Library

    function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
        require((c = a - b) < a);
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
        require((c = a + b) > a);
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


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables for timed transfer functionality
    mapping (address => uint256) public timedTransferWindows;
    mapping (address => uint256) public timedTransferAmounts;
    mapping (address => address) public timedTransferRecipients;
    mapping (address => bool) public timedTransferActive;
    
    event TimedTransferScheduled(address indexed _sender, address indexed _recipient, uint256 _amount, uint256 _windowEnd);
    event TimedTransferExecuted(address indexed _sender, address indexed _recipient, uint256 _amount);
    
    /**
    * @notice Schedule a timed transfer that can be executed within a specific time window
    * @param _recipient The address to receive the tokens
    * @param _amount The amount of tokens to transfer
    * @param _windowDuration Duration in seconds for the transfer window
    */
    function setTimedTransferWindow(address _recipient, uint256 _amount, uint256 _windowDuration) public {
        require(_recipient != address(0));
        require(_amount > 0);
        require(_windowDuration > 0);
        require(balanceOf[msg.sender] >= _amount);
        
        // Set the transfer window end time using block.timestamp
        timedTransferWindows[msg.sender] = block.timestamp + _windowDuration;
        timedTransferAmounts[msg.sender] = _amount;
        timedTransferRecipients[msg.sender] = _recipient;
        timedTransferActive[msg.sender] = true;
        
        // Lock the tokens by reducing sender's balance
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_amount);
        
        TimedTransferScheduled(msg.sender, _recipient, _amount, timedTransferWindows[msg.sender]);
    }
    
    /**
    * @notice Execute a previously scheduled timed transfer
    * @dev Can only be called within the time window and by the original sender
    */
    function executeTimedTransfer() public {
        require(timedTransferActive[msg.sender]);
        require(timedTransferWindows[msg.sender] > 0);
        
        // Vulnerability: Using block.timestamp for precise timing control
        // Miners can manipulate timestamp within certain bounds
        if (block.timestamp <= timedTransferWindows[msg.sender]) {
            // Transfer is still valid
            address recipient = timedTransferRecipients[msg.sender];
            uint256 amount = timedTransferAmounts[msg.sender];
            
            balanceOf[recipient] = balanceOf[recipient].add(amount);
            
            // Clear the timed transfer
            timedTransferActive[msg.sender] = false;
            timedTransferWindows[msg.sender] = 0;
            timedTransferAmounts[msg.sender] = 0;
            timedTransferRecipients[msg.sender] = address(0);
            
            Transfer(msg.sender, recipient, amount);
            TimedTransferExecuted(msg.sender, recipient, amount);
        } else {
            // Transfer window has expired, return tokens to sender
            balanceOf[msg.sender] = balanceOf[msg.sender].add(timedTransferAmounts[msg.sender]);
            
            // Clear the timed transfer
            timedTransferActive[msg.sender] = false;
            timedTransferWindows[msg.sender] = 0;
            timedTransferAmounts[msg.sender] = 0;
            timedTransferRecipients[msg.sender] = address(0);
        }
    }
    
    /**
    * @notice Cancel a scheduled timed transfer and return tokens to sender
    * @dev Can only be called by the original sender
    */
    function cancelTimedTransfer() public {
        require(timedTransferActive[msg.sender]);
        require(timedTransferAmounts[msg.sender] > 0);
        
        // Return locked tokens to sender
        balanceOf[msg.sender] = balanceOf[msg.sender].add(timedTransferAmounts[msg.sender]);
        
        // Clear the timed transfer
        timedTransferActive[msg.sender] = false;
        timedTransferWindows[msg.sender] = 0;
        timedTransferAmounts[msg.sender] = 0;
        timedTransferRecipients[msg.sender] = address(0);
    }
    // === END FALLBACK INJECTION ===

    function Paymec() public {balanceOf[msg.sender] = totalSupply;}

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
        Transfer(msg.sender, _to, _value);
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
        Transfer(_from, _to, _value);
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
        Approval(msg.sender, _spender, _value);
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