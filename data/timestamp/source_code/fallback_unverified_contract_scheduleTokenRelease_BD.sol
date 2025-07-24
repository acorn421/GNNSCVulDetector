/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTokenRelease
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
 * This vulnerability introduces timestamp dependence through a multi-transaction token release mechanism. The vulnerability requires: 1) First transaction to schedule tokens with scheduleTokenRelease(), 2) Waiting for the release time, 3) Second transaction to claim tokens with claimScheduledTokens(). The vulnerability lies in the reliance on 'now' (block.timestamp) which can be manipulated by miners within a 15-second window, allowing early release of tokens or denial of legitimate claims.
 */
pragma solidity ^0.4.18;
contract EIP20Interface {    
    uint256 public totalSupply;
    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
contract zpzToken is EIP20Interface {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
   
    string public name;                   
    uint8 public decimals;                
    string public symbol;                 

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These moved out of constructor to be at contract level, without 'public' for mappings
    mapping (address => uint256) releaseTimes;
    mapping (address => uint256) releaseAmounts;
    // === END DECLARATIONS ===

    function zpzToken(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               
        totalSupply = _initialAmount;                        
        name = _tokenName;                                   
        decimals = _decimalUnits;                            
        symbol = _tokenSymbol;                               
    }

    function scheduleTokenRelease(address _beneficiary, uint256 _amount, uint256 _releaseTime) public returns (bool success) {
        require(balances[msg.sender] >= _amount);
        require(_releaseTime > now);
        
        balances[msg.sender] -= _amount;
        releaseTimes[_beneficiary] = _releaseTime;
        releaseAmounts[_beneficiary] = _amount;
        
        return true;
    }

    function claimScheduledTokens() public returns (bool success) {
        require(releaseAmounts[msg.sender] > 0);
        require(now >= releaseTimes[msg.sender]);
        
        uint256 amount = releaseAmounts[msg.sender];
        releaseAmounts[msg.sender] = 0;
        releaseTimes[msg.sender] = 0;
        balances[msg.sender] += amount;
        
        Transfer(address(0), msg.sender, amount);
        return true;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
