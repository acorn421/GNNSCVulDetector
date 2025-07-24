/*
 * ===== SmartInject Injection Details =====
 * Function      : createTimelockInstallment
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This function creates a stateful timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability stems from using block.timestamp for time-based calculations in installment plans. An attacker (miner) can manipulate block timestamps to affect when installments become available, potentially allowing premature or delayed releases. The vulnerability is stateful because it stores timestamp-dependent data that persists across transactions, and multi-transaction because it requires: 1) Creating the installment plan, 2) Waiting for time conditions, 3) Claiming installments. The state persists in the installmentPlans mapping and affects future claim operations.
 */
pragma solidity ^0.4.10;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract InstallmentCoin{
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timelock functionality
    struct InstallmentPlan {
        uint256 totalAmount;
        uint256 releasedAmount;
        uint256 startTime;
        uint256 installmentDuration;
        uint256 numberOfInstallments;
        bool isActive;
    }
    
    mapping(address => mapping(address => InstallmentPlan)) public installmentPlans;
    mapping(address => uint256) public lastClaimTime;
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function InstallmentCoin(){
        balanceOf[msg.sender] = 1000000000000; // Give the creator all initial tokens
        totalSupply = 1000000000000;                        // Update total supply
        name = "installment coin";                                   // Set the name for display purposes
        symbol = "ISC";                               // Set the symbol for display purposes
        decimals = 4;                            // Amount of decimals for display purposes
    }

    /// @notice Create a timelock installment plan for beneficiary
    /// @param _beneficiary The address that will receive installments
    /// @param _totalAmount Total amount to be released over time
    /// @param _duration Duration between installments in seconds
    /// @param _installments Number of installments
    function createTimelockInstallment(address _beneficiary, uint256 _totalAmount, uint256 _duration, uint256 _installments) public {
        require(_beneficiary != 0x0);
        require(_totalAmount > 0);
        require(_duration > 0);
        require(_installments > 0);
        require(balanceOf[msg.sender] >= _totalAmount);
        require(!installmentPlans[msg.sender][_beneficiary].isActive);
        
        // Transfer tokens to contract control
        balanceOf[msg.sender] -= _totalAmount;
        
        // Create installment plan - VULNERABLE: uses block.timestamp
        installmentPlans[msg.sender][_beneficiary] = InstallmentPlan({
            totalAmount: _totalAmount,
            releasedAmount: 0,
            startTime: block.timestamp,  // VULNERABILITY: Miner can manipulate
            installmentDuration: _duration,
            numberOfInstallments: _installments,
            isActive: true
        });
        
        lastClaimTime[_beneficiary] = block.timestamp;  // VULNERABILITY: Timestamp dependence
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}