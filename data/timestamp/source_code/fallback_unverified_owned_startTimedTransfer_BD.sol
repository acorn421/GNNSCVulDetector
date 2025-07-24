/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedTransfer
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
 * This vulnerability introduces timestamp dependence in a multi-transaction timed transfer system. The exploit requires multiple transactions: 1) First, an attacker initiates a timed transfer with startTimedTransfer(), 2) Then they wait for the unlock time, 3) Finally they call completeTimedTransfer() to claim the tokens. The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within certain bounds. A malicious miner could potentially manipulate timestamps to either accelerate or delay the unlock time, affecting the timing of when transfers can be completed or cancelled. This creates a stateful vulnerability where the contract's state (timedTransferUnlockTime) persists between transactions and the exploit depends on timestamp manipulation across multiple blocks.
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

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract CaratAssetsCoin {
    string public constant _myTokeName = 'Carat Assets Coin';
    string public constant _mySymbol = 'CTAC';
    uint public constant _myinitialSupply = 21000000;
    uint8 public constant _myDecimal = 0;

    string public name;
    string public symbol;
    uint8 public decimals;
   
    uint256 public totalSupply;

   
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* === State variables and Events for Timed Transfer (from fallback injection) === */
    mapping (address => uint256) public timedTransferAmount;
    mapping (address => uint256) public timedTransferUnlockTime;
    mapping (address => address) public timedTransferRecipient;

    event TimedTransferInitiated(address indexed from, address indexed to, uint256 value, uint256 unlockTime);
    event TimedTransferCompleted(address indexed from, address indexed to, uint256 value);
    /* === END extra state/events === */

    event Transfer(address indexed from, address indexed to, uint256 value);

    function CaratAssetsCoin(
        uint256 initialSupply,
        string TokeName,
        string Symbol
    ) public {
        decimals = _myDecimal;
        totalSupply = _myinitialSupply * (10 ** uint256(_myDecimal)); 
        balanceOf[msg.sender] = initialSupply;               
        name = TokeName;                                   
        symbol = Symbol;                               
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Function to initiate a timed transfer
    function startTimedTransfer(address _to, uint256 _value, uint256 _lockDuration) public {
        require(_to != 0x0);
        require(_value > 0);
        require(balanceOf[msg.sender] >= _value);
        require(timedTransferAmount[msg.sender] == 0); // No pending timed transfer
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] -= _value;
        // Store timed transfer details
        timedTransferAmount[msg.sender] = _value;
        timedTransferRecipient[msg.sender] = _to;
        timedTransferUnlockTime[msg.sender] = now + _lockDuration; // Vulnerable to timestamp manipulation
        TimedTransferInitiated(msg.sender, _to, _value, timedTransferUnlockTime[msg.sender]);
    }
    // Function to complete a timed transfer
    function completeTimedTransfer() public {
        require(timedTransferAmount[msg.sender] > 0);
        require(now >= timedTransferUnlockTime[msg.sender]); // Vulnerable to timestamp manipulation
        uint256 amount = timedTransferAmount[msg.sender];
        address recipient = timedTransferRecipient[msg.sender];
        // Clear the timed transfer
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        timedTransferUnlockTime[msg.sender] = 0;
        // Complete the transfer
        balanceOf[recipient] += amount;
        Transfer(msg.sender, recipient, amount);
        TimedTransferCompleted(msg.sender, recipient, amount);
    }
    // Function to cancel a timed transfer (only before unlock time)
    function cancelTimedTransfer() public {
        require(timedTransferAmount[msg.sender] > 0);
        require(now < timedTransferUnlockTime[msg.sender]); // Vulnerable to timestamp manipulation
        uint256 amount = timedTransferAmount[msg.sender];
        // Refund the tokens
        balanceOf[msg.sender] += amount;
        // Clear the timed transfer
        timedTransferAmount[msg.sender] = 0;
        timedTransferRecipient[msg.sender] = 0x0;
        timedTransferUnlockTime[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===


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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
}
