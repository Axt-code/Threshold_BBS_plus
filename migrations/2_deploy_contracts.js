// var G2 = artifacts.require("./libraries/BN256G2");
// var bnCurve = artifacts.require("./libraries/G");
// var Request = artifacts.require("./contracts/Request");
// var Params = artifacts.require("./contracts/Params");
// var Verify = artifacts.require("./contracts/Verify");
// var Opening = artifacts.require("./contracts/Opening");
// var Issue = artifacts.require("./contracts/Issue");

// module.exports = function (deployer) {

//   deployer.deploy(G2, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});
//   deployer.link(G2, bnCurve);
//   deployer.deploy(bnCurve, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});

//   deployer.link(bnCurve, Verify);
//   deployer.link(G2, Verify);
//   deployer.deploy(Verify, {from: "0x9017224b425135EF21DaD7b61E1C8DDEaf1D5034"});

//   deployer.link(bnCurve, Params);
//   deployer.deploy(Params, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});

//   deployer.link(bnCurve, Request);
//   deployer.link(G2, Request);
//   deployer.deploy(Request, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});

//   deployer.deploy(Issue, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});

//   deployer.deploy(Opening, {from: "0xc804EFd57ae0038d46Dd9d9225Ece639D3098E66"});

// };


var G2 = artifacts.require("../libraries/BN256G2.sol");
var BnCurve = artifacts.require("../libraries/G.sol");
// var Request = artifacts.require("./contracts/Request");
var Params = artifacts.require("./contracts/Params");
// var Verify = artifacts.require("./contracts/Verify");
// var Opening = artifacts.require("./contracts/Opening");
// var Issue = artifacts.require("./contracts/Issue");
deployment_address = "0x9925A22E6E8Ddae43a8581c277Ce7419f04c0c6f"
param_address = "0x645FE2FFEfC64B9A691FE9771A73572e72efE62b"
validator_1 = "0x1b82F37E048e3b1d3bD4846E726fac1352a54634"
validator_2 = "0x4D209e704f6c487420d159f3Dd9D16F8EA7305A6"
validator_3 = "0x21B5bB6E595bAaC465C21CEc252f892A74eA5164"


module.exports = async function (deployer) {

  await deployer.deploy(G2, { from: deployment_address });
  const g2 = await G2.deployed()

  await deployer.link(G2, BnCurve);
  await deployer.deploy(BnCurve, { from: deployment_address });
  const bnCurve = await BnCurve.deployed()

  await deployer.link(BnCurve, Params);
  await deployer.deploy(Params, { from: deployment_address });
  const params = await Params.deployed()


  // console.log(opening.address);
  // console.log(issue.address);
  // console.log(request.address);
  console.log(params.address);
  console.log(deployment_address);
  console.log(param_address);
  console.log(validator_1);
  console.log(validator_2);
  console.log(validator_3);
  // console.log(verify.address);


};