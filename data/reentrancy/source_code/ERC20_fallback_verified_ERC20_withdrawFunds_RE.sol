/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawFunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability that requires multiple transactions to exploit. First, an attacker must call requestWithdrawal() to set up pending withdrawals, then call withdrawFunds() which makes an external call before updating the state. The vulnerability is stateful because it relies on the pendingWithdrawals mapping persisting between transactions. An attacker can create a malicious contract that re-enters withdrawFunds() during the external call, allowing them to drain more funds than they should be able to withdraw.
 */
pragma solidity ^0.4.21;

/*
  BASIC ERC20 Sale Contract
  Create this Sale contract first!
     Sale(address ethwallet)   // this will send the received ETH funds to this address
  @author Hunter Long
  @repo https://github.com/hunterlong/ethereum-ico-contract
*/

contract ERC20 {
  uint public totalSupply;
  uint public maxMintable;
  function balanceOf(address who) constant returns (uint);
  function allowance(address owner, address spender) constant returns (uint);
  function transfer(address to, uint value) returns (bool ok);
  function transferFrom(address from, address to, uint value) returns (bool ok);
  function approve(address spender, uint value) returns (bool ok);
  function mintToken(address to, uint256 value) returns (uint256);
  function changeTransfer(bool allowed);
}

contract Sale {

    uint256 public maxMintable;
    uint256 public totalMinted;
    uint256 public fondTokens;
    uint256 public exchangeRate;
    
    uint public startBlock;
    uint public coefficient;
    bool public isFunding;
    ERC20 public Token;
    address public ETHWallet;

    bool private configSet;
    address public creator;
    address public desiredUsdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public desiredUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public desiredBusd = 0x4Fabb145d64652a948d72533023f6E7A623C7C53;
    address public desiredDai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalInProgress;

    function Sale(address _wallet) public {
        startBlock = block.number;
        maxMintable = 1500000000000000000000000000; // 15KKK max sellable (18 decimals)
        totalMinted = 0;
        ETHWallet = _wallet;
        isFunding = false;
        creator = msg.sender;
        exchangeRate = 10;
        fondTokens= 500000000000000000000000000;
        coefficient = 10;
        // createFondTokens();
    }

    function requestWithdrawal(uint256 _amount) external {
        require(msg.sender == creator || msg.sender == ETHWallet);
        require(_amount > 0);
        require(address(this).balance >= _amount);
        
        pendingWithdrawals[msg.sender] += _amount;
    }
    
    function withdrawFunds() external {
        require(pendingWithdrawals[msg.sender] > 0);
        require(!withdrawalInProgress[msg.sender]);
        
        uint256 amount = pendingWithdrawals[msg.sender];
        withdrawalInProgress[msg.sender] = true;
        
        // Vulnerable to reentrancy - external call before state update
        if (msg.sender.call.value(amount)()) {
            pendingWithdrawals[msg.sender] = 0;
            withdrawalInProgress[msg.sender] = false;
        } else {
            withdrawalInProgress[msg.sender] = false;
            revert();
        }
    }

    // setup function to be ran only 1 time
    // setup token address
    // setup end Block number
    function setup(address token_address) {
        require(!configSet);
        Token = ERC20(token_address);
        configSet = true;
        createFondTokens();
    }

    function closeSale() external {
      require(msg.sender==creator);
      isFunding = false;
    }
    
    function startSale() external {
      require(msg.sender==creator);
      require(configSet);
      require(isFunding == false);
      isFunding = true;
    }

    // function () payable {
    //     require(msg.value>0);
    //     require(isFunding);
    //     uint256 amount = msg.value * exchangeRate;
    //     uint256 total = totalMinted + amount;
    //     require(total<=maxMintable);
    //     totalMinted += total;
    //     ETHWallet.transfer(msg.value);
    //     Token.mintToken(msg.sender, amount);
    // }

    // CONTRIBUTE FUNCTION
    // converts ETH to TOKEN and sends new TOKEN to the sender
    function depositUsdt(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredUsdt).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

    function depositUsdc(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredUsdc).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

     function depositBusd(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredBusd).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

     function depositDai(uint256 _amount) external payable {
        require(_amount>1000000000000000000);
        require(isFunding);
        uint256 amount = _amount * exchangeRate;
        uint256 total = totalMinted + amount;
        require(total<=maxMintable);
        totalMinted += amount;
        ERC20(desiredDai).transferFrom(msg.sender, ETHWallet, _amount);
        Token.mintToken(msg.sender, amount);
    }

    // update the USD/COIN rate
    function updateRate(uint256 rate) external {
        require(msg.sender==creator);
        exchangeRate = rate;
    }

    function updateCoefficient(uint256 _coefficient) external {
        require(msg.sender==creator);
        require(10<_coefficient);
        require(_coefficient<50);
        coefficient = _coefficient;
    }

    // change creator address
    function changeCreator(address _creator) external {
        require(msg.sender==creator);
        creator = _creator;
    }

    function changeEthWallet(address ethWallet) external {
        require(msg.sender==creator);
        ETHWallet = ethWallet;
    }

    function createFondTokens() internal {
        // TOTAL SUPPLY = 5,000,000
     require(msg.sender==creator);
     Token.mintToken(ETHWallet, fondTokens);         
    }
}
