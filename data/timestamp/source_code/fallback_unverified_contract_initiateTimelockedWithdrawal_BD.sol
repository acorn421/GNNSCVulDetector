/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimelockedWithdrawal
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
 * This injection adds a timelocked withdrawal mechanism that is vulnerable to timestamp dependence. The vulnerability requires multiple transactions to exploit: 1) First, a user initiates a withdrawal request, 2) Then they must wait for the timelock period, 3) Finally, they execute the withdrawal. The vulnerability lies in the reliance on 'now' (block.timestamp) for time validation, which can be manipulated by miners within a ~900 second window. A malicious miner could manipulate timestamps to either prevent legitimate withdrawals or allow premature withdrawals. The state persists between transactions through the withdrawalRequests and withdrawalTimestamps mappings.
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

contract TokenMACHU is owned {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timelocked withdrawals (moved outside constructor)
    mapping (address => uint256) public withdrawalRequests;
    mapping (address => uint256) public withdrawalTimestamps;
    uint256 public withdrawalDelay = 1 days;
    
    event WithdrawalRequested(address indexed user, uint256 amount, uint256 unlockTime);
    event WithdrawalExecuted(address indexed user, uint256 amount);
    // === END VARIABLE DECLARATIONS ===

    function TokenMACHU(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }
    
    // Function to initiate a timelocked withdrawal
    function initiateTimelockedWithdrawal(uint256 _amount) public {
        require(balanceOf[msg.sender] >= _amount);
        require(_amount > 0);
        
        // Store the withdrawal request
        withdrawalRequests[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = now + withdrawalDelay;
        
        // Lock the tokens by transferring to contract
        _transfer(msg.sender, this, _amount);
        
        WithdrawalRequested(msg.sender, _amount, withdrawalTimestamps[msg.sender]);
    }
    
    // Function to execute the timelocked withdrawal
    function executeTimelockedWithdrawal() public {
        require(withdrawalRequests[msg.sender] > 0);
        require(now >= withdrawalTimestamps[msg.sender]); // Vulnerable to timestamp manipulation
        
        uint256 amount = withdrawalRequests[msg.sender];
        
        // Clear the withdrawal request
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        
        // Transfer tokens back to user
        _transfer(this, msg.sender, amount);
        
        WithdrawalExecuted(msg.sender, amount);
    }
    
    // Function to cancel a pending withdrawal
    function cancelTimelockedWithdrawal() public {
        require(withdrawalRequests[msg.sender] > 0);
        
        uint256 amount = withdrawalRequests[msg.sender];
        
        // Clear the withdrawal request
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        
        // Return tokens to user
        _transfer(this, msg.sender, amount);
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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
    }

    function () public payable {
        revert();
    }
}
