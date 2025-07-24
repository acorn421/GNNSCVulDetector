/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Added external call to a burn registry contract before state updates, creating a classic reentrancy vulnerability. The external call allows the called contract to re-enter this function while the state variables (_totalSupply and balances) haven't been updated yet. This creates a window where the same tokens can be burned multiple times across different transactions. The vulnerability is stateful and multi-transaction because: 1) It requires the burnRegistry to be set in a previous transaction, 2) The attacker needs to deploy a malicious registry contract that can perform reentrancy, and 3) The exploitation happens through multiple calls where state inconsistencies accumulate across transactions. Each reentrant call sees the old state values, allowing the attacker to burn more tokens than they actually possess.
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// BurnRegistry interface as required for reentrancy injection
contract BurnRegistry {
    function notifyBurn(address, uint256) public;
}

// ERC20 Token Smart Contract
contract DraperSolutionsToken {
    
    string public constant name = "Draper Solutions Token";
    string public constant symbol = "DST";
    uint8 public constant decimals = 10;
    uint public _totalSupply = 10000000000000000;
    uint256 public RATE = 1;
    bool public isMinting = true;
    bool public isExchangeListed = false;
    string public constant generatedBy  = "drapersolutions.com";
    
    using SafeMath for uint256;
    address public owner;
    address public burnRegistry;
    
     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor
    constructor() public payable {
        owner = 0x37b1f60843a9ca412435e62d41bff145f9e0e6f0; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) onlyOwner {
         require(balances[msg.sender] >= _value && _value > 0 );
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         // Notify external burn registry before state updates
         if(burnRegistry != address(0)) {
             BurnRegistry(burnRegistry).notifyBurn(msg.sender, _value);
         }
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
    }

    // This function creates Tokens  
     function createTokens() payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
        }
        else{
            revert();
        }
    }

    function endCrowdsale() onlyOwner {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner {
        RATE = _value;
    }

    function totalSupply() constant returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value)  returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value)  returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns(bool){
        allowed[msg.sender][_spender] = _value; 
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
