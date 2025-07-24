/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawDividends
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 17 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * This injection adds a dividend distribution system that contains a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to call calculateDividend() to set up the dividend balance state, 2) Second transaction to call withdrawDividends() which is vulnerable to reentrancy because it makes an external call before updating state variables. The vulnerability persists across multiple transactions through the dividendBalance and dividendClaimed state mappings, making it a classic multi-transaction reentrancy attack where an attacker can drain funds by calling back into withdrawDividends before the state is properly updated.
 */
pragma solidity ^0.4.16;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}


contract tokenRecipient {
  event receivedEther(address sender, uint amount);
  event receivedTokens(address _from, uint256 _value, address _token, bytes _extraData);

  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public {
    Token t = Token(_token);
    require(t.transferFrom(_from, this, _value));
    receivedTokens(_from, _value, _token, _extraData);
  }

  function () payable public {
    receivedEther(msg.sender, msg.value);
  }
}

contract Token {
  mapping (address => uint256) public balanceOf;
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

/**
 * QWoodDAO contract
 */
contract QWoodDAO is Ownable, tokenRecipient {

  uint public minimumQuorum;
  uint public debatingPeriodInMinutes;
  Proposal[] public proposals;
  uint public numProposals;
  Token public sharesTokenAddress;
  uint256 public minShare;

  event ProposalAdded(uint proposalID, address recipient, uint amount, string description);
  event Voted(uint proposalID, bool position, address voter);
  event ProposalTallied(uint proposalID, uint result, uint quorum, bool active);
  event ChangeOfRules(uint newMinimumQuorum, uint newDebatingPeriodInMinutes, address newSharesTokenAddress, uint256 newMinShare);

  struct Vote {
    bool inSupport;
    address voter;
  }

  struct Proposal {
    address recipient;
    uint amount;
    string description;
    uint minExecutionDate;
    bool executed;
    bool proposalPassed;
    uint numberOfVotes;
    bytes32 proposalHash;
    Vote[] votes;
    mapping (address => bool) voted;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) dividendBalance;
    mapping(address => bool) dividendClaimed;
    uint256 totalDividends;
    bool dividendsEnabled;
  }

  // Dividend functions for the Proposal struct (for fallback injection)
  // Syntax fix: these need to be outside the struct and refer to a specific Proposal
  function enableDividends(uint proposalId) public onlyOwner {
      // Access Proposal by reference
      Proposal storage p = proposals[proposalId];
      p.dividendsEnabled = true;
  }
  function distributeDividends(uint proposalId) public payable onlyOwner {
      Proposal storage p = proposals[proposalId];
      require(p.dividendsEnabled);
      require(msg.value > 0);
      p.totalDividends = msg.value;
      // Note: per original comment, does not reset all claims.
  }
  function calculateDividend(uint proposalId, address shareholder) public returns (uint256) {
      Proposal storage p = proposals[proposalId];
      require(p.dividendsEnabled);
      require(p.totalDividends > 0);
      uint256 shareholderBalance = sharesTokenAddress.balanceOf(shareholder);
      require(shareholderBalance > 0);
      uint256 dividend = (p.totalDividends * shareholderBalance) / 1000000; // Assume total supply is 1M
      p.dividendBalance[shareholder] = dividend;
      return dividend;
  }
  function withdrawDividends(uint proposalId) public {
      Proposal storage p = proposals[proposalId];
      require(p.dividendsEnabled);
      require(p.dividendBalance[msg.sender] > 0);
      require(!p.dividendClaimed[msg.sender]);
      uint256 amount = p.dividendBalance[msg.sender];
      // VULNERABILITY: External call before state update
      require(msg.sender.call.value(amount)());
      // Update state after external call - reentrancy vulnerability preserved
      p.dividendClaimed[msg.sender] = true;
      p.dividendBalance[msg.sender] = 0;
  }

  // Modifier that allows only shareholders to vote and create new proposals
  modifier onlyShareholders {
    require(sharesTokenAddress.balanceOf(msg.sender) > minShare);
    _;
  }

  /**
   * Constructor function
   *
   * First time setup
   */
  function QWoodDAO(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) payable public {
    changeVotingRules(sharesAddress, minimumSharesToPassAVote, minutesForDebate, minimumShare);
  }

  /**
   * Change voting rules
   *
   * Make so that proposals need to be discussed for at least `minutesForDebate/60` hours
   * and all voters combined must own more than `minimumSharesToPassAVote` shares of token `sharesAddress` to be executed
   *
   * @param sharesAddress token address
   * @param minimumSharesToPassAVote proposal can vote only if the sum of shares held by all voters exceed this number
   * @param minutesForDebate the minimum amount of delay between when a proposal is made and when it can be executed
   * @param minimumShare the minimum share of shareholders
   */
  function changeVotingRules(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) onlyOwner public {
    sharesTokenAddress = Token(sharesAddress);
    if (minimumSharesToPassAVote == 0 ) minimumSharesToPassAVote = 1;
    minimumQuorum = minimumSharesToPassAVote;
    debatingPeriodInMinutes = minutesForDebate;
    minShare = minimumShare;
    ChangeOfRules(minimumQuorum, debatingPeriodInMinutes, sharesTokenAddress, minShare);
  }

  /**
   * Add Proposal
   *
   * Propose to send `weiAmount / 1e18` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   *
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send, in wei
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposal(
    address beneficiary,
    uint weiAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    proposalID = proposals.length++;
    Proposal storage p = proposals[proposalID];
    p.recipient = beneficiary;
    p.amount = weiAmount;
    p.description = jobDescription;
    p.proposalHash = keccak256(beneficiary, weiAmount, transactionBytecode);
    p.minExecutionDate = now + debatingPeriodInMinutes * 1 minutes;
    p.executed = false;
    p.proposalPassed = false;
    p.numberOfVotes = 0;
    ProposalAdded(proposalID, beneficiary, weiAmount, jobDescription);
    numProposals = proposalID+1;

    return proposalID;
  }

  /**
   * Add proposal in Ether
   *
   * Propose to send `etherAmount` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   * This is a convenience function to use if the amount to be given is in round number of ether units.
   *
   * @param beneficiary who to send the ether to
   * @param etherAmount amount of ether to send
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposalInEther(
    address beneficiary,
    uint etherAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    return newProposal(beneficiary, etherAmount * 1 ether, jobDescription, transactionBytecode);
  }

  /**
   * Check if a proposal code matches
   *
   * @param proposalNumber ID number of the proposal to query
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send
   * @param transactionBytecode bytecode of transaction
   */
  function checkProposalCode(
    uint proposalNumber,
    address beneficiary,
    uint weiAmount,
    bytes transactionBytecode
  )
  constant public
  returns (bool codeChecksOut)
  {
    Proposal storage p = proposals[proposalNumber];
    return p.proposalHash == keccak256(beneficiary, weiAmount, transactionBytecode);
  }

  /**
   * Log a vote for a proposal
   *
   * Vote `supportsProposal? in support of : against` proposal #`proposalNumber`
   *
   * @param proposalNumber number of proposal
   * @param supportsProposal either in favor or against it
   */
  function vote(
    uint proposalNumber,
    bool supportsProposal
  )
  onlyShareholders public
  returns (uint voteID)
  {
    Proposal storage p = proposals[proposalNumber];
    require(p.voted[msg.sender] != true);

    voteID = p.votes.length++;
    p.votes[voteID] = Vote({inSupport: supportsProposal, voter: msg.sender});
    p.voted[msg.sender] = true;
    p.numberOfVotes = voteID +1;
    Voted(proposalNumber,  supportsProposal, msg.sender);
    return voteID;
  }

  /**
   * Finish vote
   *
   * Count the votes proposal #`proposalNumber` and execute it if approved
   *
   * @param proposalNumber proposal number
   * @param transactionBytecode optional: if the transaction contained a bytecode, you need to send it
   */
  function executeProposal(uint proposalNumber, bytes transactionBytecode) public {
    Proposal storage p = proposals[proposalNumber];

    require(now > p.minExecutionDate                                             // If it is past the voting deadline
    && !p.executed                                                          // and it has not already been executed
    && p.proposalHash == keccak256(p.recipient, p.amount, transactionBytecode)); // and the supplied code matches the proposal...

    // ...then tally the results
    uint quorum = 0;
    uint yea = 0;
    uint nay = 0;

    for (uint i = 0; i <  p.votes.length; ++i) {
      Vote storage v = p.votes[i];
      uint voteWeight = sharesTokenAddress.balanceOf(v.voter);
      quorum += voteWeight;
      if (v.inSupport) {
        yea += voteWeight;
      } else {
        nay += voteWeight;
      }
    }

    require(quorum >= minimumQuorum); // Check if a minimum quorum has been reached

    if (yea > nay ) {
      // Proposal passed; execute the transaction

      p.executed = true;
      require(p.recipient.call.value(p.amount)(transactionBytecode));

      p.proposalPassed = true;
    } else {
      // Proposal failed
      p.proposalPassed = false;
    }

    // Fire Events
    ProposalTallied(proposalNumber, yea - nay, quorum, p.proposalPassed);
  }
}
