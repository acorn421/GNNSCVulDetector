/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenSalePhase
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
 * This vulnerability exploits timestamp dependence where miners can manipulate block timestamps to affect token sale phases. The vulnerability is stateful and multi-transaction: 1) Owner sets sale periods with initializeSalePeriods(), 2) setTokenSalePhase() is called to activate phases based on timestamp, 3) Users participate in sales. Malicious miners can manipulate timestamps to extend presale periods to get bonus tokens or prematurely end sales. The state (presaleActive, mainSaleActive) persists between transactions, and exploitation requires multiple function calls across different transactions.
 */
pragma solidity ^0.4.8;
 
// ----------------------------------------------------------------------------------------------
// Sample fixed supply token contract
// Enjoy. (c) BokkyPooBah 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------
 
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/issues/20
contract ERC20Interface {
    // Get the total token supply
    function totalSupply() constant returns (uint256 totalSupply);
 
    // Get the account balance of another account with address _owner
    function balanceOf(address _owner) constant returns (uint256 balance);
 
    // Send _value amount of tokens to address _to
    function transfer(address _to, uint256 _value) returns (bool success);
 
    // Send _value amount of tokens from address _from to address _to
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
 
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    // this function is required for some DEX functionality
    function approve(address _spender, uint256 _value) returns (bool success);
 
    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
 
    // Triggered when tokens are transferred.
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
 
    // Triggered whenever approve(address _spender, uint256 _value) is called.
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
 
contract FuturecomToken is ERC20Interface {
    string public constant symbol = "FUCOS";
    string public constant name = "Futurecom Interactive Token";
    uint8 public constant decimals = 18;
    uint256 _totalSupply = 42000000000000000000000000;
    
    // Owner of this contract
    address public owner;
 
    // Balances for each account
    mapping(address => uint256) balances;
 
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping (address => uint256)) allowed;
 
    // Functions with this modifier can only be executed by the owner
    modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // State variables for token sale phases
    uint256 public presaleEndTime;
    uint256 public mainSaleEndTime;
    bool public presaleActive = false;
    bool public mainSaleActive = false;
    mapping(address => uint256) public presaleContributions;
    mapping(address => uint256) public mainSaleContributions;
    
    // Function to set token sale phase based on timestamp
    function setTokenSalePhase() public {
        if (now <= presaleEndTime && !presaleActive) {
            presaleActive = true;
            mainSaleActive = false;
        } else if (now > presaleEndTime && now <= mainSaleEndTime && !mainSaleActive) {
            presaleActive = false;
            mainSaleActive = true;
        } else if (now > mainSaleEndTime) {
            presaleActive = false;
            mainSaleActive = false;
        }
    }
    
    // Function to initialize sale periods (can be called multiple times)
    function initializeSalePeriods(uint256 _presaleEnd, uint256 _mainSaleEnd) public onlyOwner {
        presaleEndTime = _presaleEnd;
        mainSaleEndTime = _mainSaleEnd;
    }
    
    // Function to participate in presale
    function participateInPresale() public payable {
        require(presaleActive, "Presale not active");
        require(msg.value > 0, "Must send ETH");
        
        presaleContributions[msg.sender] += msg.value;
        
        // Give bonus tokens during presale (20% more tokens)
        uint256 tokenAmount = (msg.value * 120) / 100;
        balances[msg.sender] += tokenAmount;
        balances[owner] -= tokenAmount;
        
        Transfer(owner, msg.sender, tokenAmount);
    }
    
    // Function to participate in main sale
    function participateInMainSale() public payable {
        require(mainSaleActive, "Main sale not active");
        require(msg.value > 0, "Must send ETH");
        
        mainSaleContributions[msg.sender] += msg.value;
        
        // Regular token distribution (1:1 ratio)
        uint256 tokenAmount = msg.value;
        balances[msg.sender] += tokenAmount;
        balances[owner] -= tokenAmount;
        
        Transfer(owner, msg.sender, tokenAmount);
    }
    // === END FALLBACK INJECTION ===

 
    // Constructor
    function FuturecomToken() {
        owner = msg.sender;
        balances[owner] = _totalSupply;
    }
 
    function totalSupply() constant returns (uint256 totalSupply) {
        totalSupply = _totalSupply;
    }
 
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    // Transfer the balance from owner's account to another account
    function transfer(address _to, uint256 _amount) returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _amount) returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
